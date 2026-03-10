import csv
import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import Optional, List
from uuid import uuid4
import subprocess
import xmltodict
import ipaddress
import json
from pathlib import Path
from backend.scanner.nvd_mapping import enrich_service_with_nvd
from pydantic import BaseModel
from backend.scanner.pcvp_scoring import pcvp_score_for_service
from backend.scanner.attack_graph import build_attack_graph
from backend.scanner.weak_creds import annotate_services_with_weak_creds
from typing import Any, Dict
from backend.llm_remediation import generate_remediation_openai
from fastapi.responses import StreamingResponse
from backend.report_generator import build_pdf_report
from io import BytesIO
import re
from typing import Tuple
import time 


def infer_exposure_from_target(target: str) -> str:
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private:
            return "internal"
        else:
            return "external"
    except ValueError:
        return "external"

NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"
IPSCAN_PATH = r"C:\Tools\AngryIP\ipscan.exe"  # ✅ add here

BASE_DIR = Path(__file__).resolve().parent
SCANS_DIR = BASE_DIR / "scans"
SCANS_DIR.mkdir(exist_ok=True)
SCAN_STATUS_FILE = SCANS_DIR / "scan_status.json"

def parse_target_and_port(raw: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns (host, port, scheme)
    Accepts:
      - "1.2.3.4"
      - "1.2.3.4:3000"
      - "example.com:8080"
      - "http://example.com:8080"
      - "https://example.com:8443"
    Note: IPv6 like [::1]:3000 not handled here (can be added).
    """
    raw = (raw or "").strip()
    scheme = None
    hostport = raw

    m = re.match(r"^(https?)://([^/]+)", raw, flags=re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        hostport = m.group(2)

    if ":" in hostport and hostport.count(":") == 1:
        host, port = hostport.split(":", 1)
        host = host.strip()
        port = port.strip()
        if port.isdigit():
            return host, port, scheme

    return hostport.strip(), None, scheme

# ✅ Added gobuster_*.done to clear list
def _clear_scan_files() -> None:
    for pattern in ("*.xml", "gobuster_*.txt", "gobuster_*.status", "gobuster_*.done", "scan_status.json"):
        for p in SCANS_DIR.glob(pattern):
            try:
                p.unlink()
            except Exception:
                pass

GOBUSTER_EXE = BASE_DIR.parent / "gobuster_Windows_x86_64" / "gobuster.exe"
GOBUSTER_WORDLIST = BASE_DIR.parent / "wordlists" / "common.txt"

app = FastAPI(title="PCVP - Privilege Contextual Vulnerability Prioritizer")

BOOT_ID = str(uuid4())

templates = Jinja2Templates(directory=str(BASE_DIR.parent / "frontend" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR.parent / "frontend" / "static")), name="static")


class ScanRequest(BaseModel):
    target: str
    description: Optional[str] = None
    exposure: Optional[str] = "auto"
    ports: Optional[str] = None

class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str
    message: Optional[str] = None
    exposure: Optional[str] = "auto"
    exposure_effective: Optional[str] = None
    gobuster_status: Optional[str] = "pending"  # ✅ track gobuster separately


class WebScanRequest(BaseModel):
    url: str
    description: Optional[str] = None


class WebScanStatus(BaseModel):
    scan_id: str
    status: str
    message: str

class RemediationRequest(BaseModel):
    scan_id: str
    ip: str
    port: int
    protocol: str = "tcp"


scan_status_store: dict[str, ScanStatus] = {}

def _save_scan_status_store() -> None:
    try:
        data = {k: v.dict() for k, v in scan_status_store.items()}
        tmp = SCAN_STATUS_FILE.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(SCAN_STATUS_FILE)
    except Exception as e:
        print(f"[SCAN STORE] Failed to save scan status store: {e}")

def is_cidr_target(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return "/" in s
    except Exception:
        return False


def run_angry_ip_discovery(scan_id: str, subnet: str) -> list[str]:
    out_csv = SCANS_DIR / f"angryip_{scan_id}.csv"

    # Convert CIDR -> start/end range for Angry IP feeder
    net = ipaddress.ip_network(subnet, strict=False)
    start_ip = str(net.network_address)
    end_ip = str(net.broadcast_address)

    cmd = [
        IPSCAN_PATH,
        "-s",                  # start scanning automatically
        "-q",                  # quit after exporting the results
        "-f:range", start_ip, end_ip,
        "-o", str(out_csv),    # exporter inferred from ".csv"
    ]

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
        creationflags=subprocess.CREATE_NO_WINDOW,  # ✅ hide Angry IP window
        startupinfo=startupinfo,
    )

    if result.returncode != 0:
        err = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
        raise Exception(f"Angry IP Scanner failed: {err or 'unknown error'}")

    if not out_csv.exists():
        return []

    alive: list[str] = []
    with out_csv.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            candidate = (row[0] or "").strip()
            try:
                ipaddress.ip_address(candidate)
                alive.append(candidate)
            except Exception:
                continue

    return sorted(set(alive), key=lambda x: tuple(int(p) for p in x.split(".")))


def run_nmap_scan_multi(scan_id: str, targets: List[str], ports: Optional[str] = None) -> None:
    """
    Runs ONE Nmap scan for multiple targets and writes:
      scans/<scan_id>.xml

    Uses a temporary file first to avoid partial XML reads.
    """
    status = scan_status_store.get(scan_id)
    if not status:
        return

    status.status = "running"
    status.message = "Nmap scan in progress (multi-host)..."
    status.gobuster_status = "skipped"
    scan_status_store[scan_id] = status
    _save_scan_status_store()

    output_file = SCANS_DIR / f"{scan_id}.xml"
    tmp_file = SCANS_DIR / f"{scan_id}.xml.tmp"

    try:
        # Remove any stale tmp
        try:
            if tmp_file.exists():
                tmp_file.unlink()
        except Exception:
            pass

        cmd = [NMAP_PATH, "-sV", "-T4"]

        if ports:
            cmd += ["-p", ports]

        # ✅ Write to tmp first
        cmd += ["-oX", str(tmp_file)]
        cmd += list(targets)

        subprocess.run(cmd, check=True, capture_output=True)

        # ✅ Atomic replace: endpoints will only see a complete XML
        if not tmp_file.exists() or tmp_file.stat().st_size < 100:
            raise RuntimeError("Nmap did not produce a valid XML output file.")

        tmp_file.replace(output_file)

        status.status = "completed"
        status.message = f"CIDR scan completed. Alive hosts scanned: {len(targets)}"

    except subprocess.CalledProcessError as e:
        err_msg = ""
        try:
            err_msg = e.stderr.decode(errors="ignore") if e.stderr else ""
        except Exception:
            err_msg = str(e)

        status.status = "failed"
        status.message = f"Scan failed: {err_msg or str(e)}"

    except Exception as e:
        status.status = "failed"
        status.message = f"Unexpected error: {e}"

    finally:
        scan_status_store[scan_id] = status
        _save_scan_status_store()
        # cleanup tmp if left behind
        try:
            if tmp_file.exists():
                tmp_file.unlink()
        except Exception:
            pass


def run_cidr_scan(scan_id: str, subnet: str, ports: Optional[str]) -> None:
    """
    1) Angry IP discovery -> alive hosts
    2) Run ONE combined Nmap scan against alive hosts
       and write scans/<scan_id>.xml (so your existing UI endpoints work)

    Also saves alive list:
      scans/alive_<scan_id>.json
    """
    st = scan_status_store.get(scan_id)
    if not st:
        return

    try:
        st.status = "running"
        st.message = "Discovering alive hosts (Angry IP Scanner)..."
        st.gobuster_status = "skipped"
        scan_status_store[scan_id] = st
        _save_scan_status_store()

        alive_hosts = run_angry_ip_discovery(scan_id, subnet)

        if not alive_hosts:
            st.status = "failed"
            st.message = "No alive hosts found in subnet."
            scan_status_store[scan_id] = st
            _save_scan_status_store()
            return

        # save alive list
        alive_path = SCANS_DIR / f"alive_{scan_id}.json"
        with alive_path.open("w", encoding="utf-8") as f:
            json.dump({"subnet": subnet, "alive": alive_hosts}, f, indent=2)

        st.message = f"Discovered {len(alive_hosts)} alive hosts. Running Nmap (combined)..."
        scan_status_store[scan_id] = st
        _save_scan_status_store()

        # ✅ IMPORTANT: run one Nmap scan for all alive hosts -> scans/<scan_id>.xml
        run_nmap_scan_multi(scan_id, alive_hosts, ports=ports)

        # run_nmap_scan_multi updates scan status to completed/failed and saves it
        return

    except Exception as e:
        st.status = "failed"
        st.message = f"CIDR scan failed: {e}"
        st.gobuster_status = "skipped"
        scan_status_store[scan_id] = st
        _save_scan_status_store()

def _normalize_webscan_error(err: str) -> str:
    e = (err or "").strip()
    if not e:
        return "Web scan failed for an unknown reason."

    low = e.lower()

    if "timeout" in low:
        return "Web scan timed out (no HTTP response on that host/port or blocked by firewall)."
    if "connection refused" in low:
        return "Web scan connection refused (no web server on that port or firewall rejected)."
    if "no such host" in low or "lookup" in low:
        return "Web scan failed (DNS/host resolution error)."
    if "tls" in low or "ssl" in low or "https" in low:
        return "Web scan failed due to TLS/SSL issue (try https://target:port if applicable)."
    if "403" in low or "forbidden" in low:
        return "Web scan appears blocked (403 Forbidden)."

    return "Web scan failed or was blocked by the target."


def _load_scan_status_store() -> None:
    if not SCAN_STATUS_FILE.exists():
        return
    try:
        with SCAN_STATUS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            try:
                scan_status_store[k] = ScanStatus(**v)
            except Exception:
                continue
    except Exception as e:
        print(f"[SCAN STORE] Failed to load scan status store: {e}")


@app.on_event("startup")
def load_in_memory_store() -> None:
    scan_status_store.clear()
    _clear_scan_files()
    

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "pcvp-backend", "boot_id": BOOT_ID}


@app.post("/scans/clear")
def clear_persisted_scans():
    try:
        if SCAN_STATUS_FILE.exists():
            SCAN_STATUS_FILE.unlink()
        scan_status_store.clear()
        _save_scan_status_store()
        return {"status": "ok", "message": "Persisted scan metadata cleared (raw files preserved)"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear scan metadata: {e}")


@app.get("/", include_in_schema=False)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def run_nmap_scan(scan_id: str, target: str, ports: Optional[str] = None):
    status = scan_status_store.get(scan_id)
    if not status:
        return

    status.status = "running"
    scan_status_store[scan_id] = status

    output_file = SCANS_DIR / f"{scan_id}.xml"

    try:
        cmd = [
            NMAP_PATH,
            "-sV",
            "-T4",
        ]

        if ports:
            cmd += ["-p", ports]  # ✅ only scan specified ports

        cmd += ["-oX", str(output_file), target]

        subprocess.run(cmd, check=True, capture_output=True)

        status.status = "nmap_done"
        status.message = "Nmap completed. Waiting for Gobuster..."

    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode(errors="ignore") if e.stderr else str(e)
        status.status = "failed"
        status.message = f"Scan failed: {err_msg}"
    except Exception as e:
        status.status = "failed"
        status.message = f"Unexpected error: {e}"
    finally:
        scan_status_store[scan_id] = status
        _save_scan_status_store()

@app.post("/scan", response_model=ScanStatus)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.target:
        raise HTTPException(status_code=400, detail="Target is required")
    try:
        ip_tmp = ipaddress.ip_address(request.target.strip())
        if ip_tmp.version == 4 and request.target.strip().endswith(".0"):
            request.target = f"{request.target.strip()}/24"
    except Exception:
        pass

    # ✅ ADD THIS (CIDR subnet scan)
    if is_cidr_target(request.target):
        scan_status_store.clear()
        _save_scan_status_store()

        scan_id = str(uuid4())
        ports = (request.ports or "").strip() or None

        status = ScanStatus(
            scan_id=scan_id,
            target=request.target,  # keep CIDR as target label
            status="pending",
            message="CIDR scan scheduled (Angry IP discovery + combined Nmap)",
            exposure=request.exposure or "auto",
            exposure_effective="internal",
            gobuster_status="skipped",
        )
        scan_status_store[scan_id] = status
        _save_scan_status_store()

        background_tasks.add_task(run_cidr_scan, scan_id, request.target, ports)
        return status
    # ✅ END CIDR BLOCK

    host, implied_port, scheme = parse_target_and_port(request.target)

    # user-provided ports (optional)
    ports = (request.ports or "").strip() or None

    # if user typed host:port and didn't provide ports separately, use that
    if implied_port and not ports:
        ports = implied_port

    exposure_choice = request.exposure or "auto"
    if exposure_choice == "auto":
        exposure_effective = infer_exposure_from_target(host)
    else:
        exposure_effective = exposure_choice

    scan_status_store.clear()
    _save_scan_status_store()

    scan_id = str(uuid4())
    status = ScanStatus(
        scan_id=scan_id,
        target=host,  # ✅ store clean host (not host:port)
        status="pending",
        message="Nmap + Gobuster scan scheduled",
        exposure=exposure_choice,
        exposure_effective=exposure_effective,
    )
    scan_status_store[scan_id] = status
    _save_scan_status_store()

    # ✅ Nmap: scan host, optionally specific ports
    background_tasks.add_task(run_nmap_scan, scan_id=scan_id, target=host, ports=ports)

    # ✅ Gobuster: build URL including scheme and port (if single port)
    netloc = host
    if ports and ports.isdigit():
        netloc = f"{host}:{ports}"

    if not scheme:
        scheme = "http"

    target_url = f"{scheme}://{netloc}"
    background_tasks.add_task(run_gobuster_scan, scan_id, target_url)

    return status
@app.get("/scan/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    status = scan_status_store.get(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")

    xml_path = SCANS_DIR / f"{scan_id}.xml"
    done_path = SCANS_DIR / f"gobuster_{scan_id}.done"

    nmap_done = xml_path.exists() and xml_path.stat().st_size > 100
    gobuster_done = done_path.exists()

    # ✅ CIDR scans skip gobuster, so don't wait for gobuster_.done
    if status.gobuster_status == "skipped":
        gobuster_done = True

    if nmap_done and gobuster_done:
        status.status = "completed"
        # if gobuster was skipped, keep it skipped; otherwise mark completed
        if status.gobuster_status != "skipped":
            status.gobuster_status = "completed"
        status.message = "Scan fully completed."
        scan_status_store[scan_id] = status
        _save_scan_status_store()

    elif nmap_done and not gobuster_done:
        status.status = "nmap_done"
        status.gobuster_status = "running"
        if status.status not in ("failed",):
            status.message = "Nmap completed. Waiting for Gobuster..."
        scan_status_store[scan_id] = status

    elif not nmap_done:
        if status.status not in ("failed",):
            status.status = "running"
            status.message = "Nmap scan in progress..."
        scan_status_store[scan_id] = status

    return status

@app.get("/scan/{scan_id}/raw")
def get_raw_scan(scan_id: str):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    with open(xml_path, "r", encoding="utf-8") as f:
        content = f.read()

    return {"scan_id": scan_id, "xml": content}

def parse_nmap_xml(xml_path: Path) -> dict:
    if not xml_path.exists():
        raise FileNotFoundError(f"XML file not found: {xml_path}")

    # ✅ Wait a bit if Nmap is still writing the file (prevents truncated XML parse)
    xml_content = ""
    for _ in range(20):  # 20 * 0.5s = 10 seconds max wait
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_content = f.read()

        if xml_content.strip() and "</nmaprun>" in xml_content:
            break

        time.sleep(0.5)

    if not xml_content.strip():
        raise ValueError("Nmap XML is empty (scan not finished yet)")

    if "</nmaprun>" not in xml_content:
        raise ValueError("Nmap XML is incomplete (scan still running). Try again in a few seconds.")

    data = xmltodict.parse(xml_content)

    nmaprun = data.get("nmaprun", {})
    raw_hosts = nmaprun.get("host", [])

    if isinstance(raw_hosts, dict):
        hosts = [raw_hosts]
    else:
        hosts = raw_hosts

    parsed = {"hosts": []}

    for host in hosts:
        addresses = host.get("address", [])
        if isinstance(addresses, dict):
            addresses = [addresses]

        ip = None
        for addr in addresses:
            if addr.get("@addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("@addr")
                break

        ports_block = host.get("ports", {}) or {}
        raw_ports = ports_block.get("port", [])
        if isinstance(raw_ports, dict):
            raw_ports = [raw_ports]

        services = []
        for p in raw_ports:
            try:
                port_id = int(p.get("@portid"))
            except (TypeError, ValueError):
                continue

            proto = p.get("@protocol", "tcp")
            state = (p.get("state") or {}).get("@state", "unknown")

            service_info = p.get("service") or {}
            service_name = service_info.get("@name")
            product = service_info.get("@product")
            version = service_info.get("@version")
            extrainfo = service_info.get("@extrainfo")

            services.append(
                {
                    "port": port_id,
                    "protocol": proto,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                }
            )

        parsed["hosts"].append({"ip": ip, "services": services})

    return parsed
@app.get("/scan/{scan_id}/parsed")
def get_parsed_scan(scan_id: str):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    try:
        parsed = parse_nmap_xml(xml_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse XML: {e}")

    return {
        "scan_id": scan_id,
        "data": parsed,
    }

@app.get("/scan/{scan_id}/nvd")
def get_scan_with_nvd(scan_id: str):
    scan_status = scan_status_store.get(scan_id)
    if not scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    if getattr(scan_status, "status", "") not in ("completed", "nmap_done"):
        raise HTTPException(status_code=400, detail=f"Scan not completed ({scan_status.status}): {scan_status.message}")

    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    try:
        parsed = parse_nmap_xml(xml_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse scan XML: {e}")

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target)
    )

    annotate_services_with_weak_creds(parsed)

    host_count = 0
    for host in parsed.get("hosts", []):
        host_count += 1
        svc_count = 0
        for svc in host.get("services", []):
            svc_count += 1
            product = svc.get("product")
            version = svc.get("version")

            try:
                svc["nvd"] = enrich_service_with_nvd(product, version)
            except Exception as nvd_err:
                svc["nvd"] = {"keyword": None, "cves": [], "error": str(nvd_err)}

            try:
                pcvp = pcvp_score_for_service(svc, exposure_effective)
                svc["pcvp_score"] = pcvp["pcvp_score"]
                svc["pcvp_level"] = pcvp["pcvp_level"]
                svc["pcvp_reasons"] = pcvp["pcvp_reasons"]
            except Exception as pcvp_err:
                svc["pcvp_score"] = 0
                svc["pcvp_level"] = "informational"
                svc["pcvp_reasons"] = []

    return {"scan_id": scan_id, "exposure": scan_status.exposure, "data": parsed}

@app.get("/scan/{scan_id}/attack-graph")
def get_attack_graph(scan_id: str):
    scan_status = scan_status_store.get(scan_id)
    if not scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    if getattr(scan_status, "status", "") not in ("completed", "nmap_done"):
        raise HTTPException(status_code=400, detail=f"Scan not completed ({scan_status.status}): {scan_status.message}")

    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    try:
        parsed = parse_nmap_xml(xml_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse scan XML: {e}")

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target)
    )

    for host in parsed.get("hosts", []):
        for svc in host.get("services", []):
            product = svc.get("product")
            version = svc.get("version")
            svc["nvd"] = enrich_service_with_nvd(product, version)

            pcvp = pcvp_score_for_service(svc, exposure_effective)
            svc["pcvp_score"] = pcvp["pcvp_score"]
            svc["pcvp_level"] = pcvp["pcvp_level"]
            svc["pcvp_reasons"] = pcvp["pcvp_reasons"]

    graph = build_attack_graph(parsed)
    return {"scan_id": scan_id, "exposure": scan_status.exposure, "graph": graph}

def run_gobuster_scan(scan_id: str, url: str) -> None:
    output_path = SCANS_DIR / f"gobuster_{scan_id}.txt"
    status_path = SCANS_DIR / f"gobuster_{scan_id}.status"
    done_path = SCANS_DIR / f"gobuster_{scan_id}.done"
    SCANS_DIR.mkdir(parents=True, exist_ok=True)

    # ✅ Mark gobuster as running
    scan_st = scan_status_store.get(scan_id)
    if scan_st:
        scan_st.gobuster_status = "running"
        scan_status_store[scan_id] = scan_st
        _save_scan_status_store()

    cmd = [
        str(GOBUSTER_EXE),
        "dir",
        "-u", url,
        "-w", str(GOBUSTER_WORDLIST),
        "-o", str(output_path),
        "-t", "30",            # a bit lower to reduce load
        "--timeout", "10s",    # ✅ increased from 2s to avoid false timeouts
        "-q",
    ]

    gobuster_failed = False
    friendly_error: Optional[str] = None

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # allow more time overall
        )

        if result.returncode != 0:
            gobuster_failed = True
            raw_err = (result.stderr or "").strip() or f"Gobuster exited with code {result.returncode}"
            friendly_error = _normalize_webscan_error(raw_err)
            with status_path.open("w", encoding="utf-8") as f:
                f.write(friendly_error)

    except subprocess.TimeoutExpired:
        gobuster_failed = True
        friendly_error = "Web scan timed out (overall gobuster timeout)."
        with status_path.open("w", encoding="utf-8") as f:
            f.write(friendly_error)

    except Exception as e:
        gobuster_failed = True
        friendly_error = _normalize_webscan_error(str(e))
        with status_path.open("w", encoding="utf-8") as f:
            f.write(friendly_error)

    finally:
        # ✅ Always write .done so UI can stop waiting
        try:
            with done_path.open("w", encoding="utf-8") as f:
                f.write("done")
        except Exception as e:
            print(f"[GOBUSTER] Failed to write .done file: {e}")

        # ✅ Mark gobuster status accurately
        scan_st = scan_status_store.get(scan_id)
        if scan_st:
            scan_st.gobuster_status = "failed" if gobuster_failed else "completed"
            scan_status_store[scan_id] = scan_st
            _save_scan_status_store()
# ✅ Now checks .done file instead of .txt file
@app.get("/webscan/{scan_id}", response_model=WebScanStatus)
def get_web_scan_status(scan_id: str):
    done_path = SCANS_DIR / f"gobuster_{scan_id}.done"
    status_path = SCANS_DIR / f"gobuster_{scan_id}.status"

    if done_path.exists():
        if status_path.exists():
            msg = status_path.read_text(encoding="utf-8", errors="ignore").strip() or "Web scan failed."
            return WebScanStatus(scan_id=scan_id, status="failed", message=msg)
        return WebScanStatus(scan_id=scan_id, status="completed", message="Gobuster scan completed.")
    else:
        return WebScanStatus(scan_id=scan_id, status="running", message="Gobuster scan is still running or not started.")

def parse_gobuster_output(path: Path) -> List[dict]:
    entries: List[dict] = []
    if not path.exists():
        return entries

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                part, rest = line.split(" (Status:", 1)
                web_path = part.strip()
                rest = rest.strip()
                status_part, size_part = rest.split(")", 1)
                status = int(status_part.strip())
                size = None
                if "[Size:" in size_part:
                    size_str = size_part.split("[Size:", 1)[1].split("]")[0].strip()
                    if size_str.isdigit():
                        size = int(size_str)
            except ValueError:
                continue

            entries.append({
                "path": web_path,
                "status": status,
                "size": size,
            })

    return entries

@app.get("/webscan/{scan_id}/results")
def get_web_scan_results(scan_id: str):
    output_path = SCANS_DIR / f"gobuster_{scan_id}.txt"
    status_path = SCANS_DIR / f"gobuster_{scan_id}.status"

    error_message = None
    if status_path.exists():
        with status_path.open("r", encoding="utf-8", errors="ignore") as f:
            error_message = f.read().strip()

    if not output_path.exists():
        if error_message:
            return {
                "scan_id": scan_id,
                "results": [],
                "error": error_message,
            }
        raise HTTPException(status_code=404, detail="Gobuster output not found yet")

    entries = parse_gobuster_output(output_path)
    return {
        "scan_id": scan_id,
        "results": entries,
        "error": error_message,
    }

@app.post("/scan/{scan_id}/remediation")
def get_llm_remediation(scan_id: str, req: RemediationRequest):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    parsed = parse_nmap_xml(xml_path)

    scan_status = scan_status_store.get(scan_id)

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status and scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target) if scan_status else "external"
    )

    annotate_services_with_weak_creds(parsed)

    target_svc = None
    for host in parsed.get("hosts", []):
        if host.get("ip") != req.ip:
            continue
        for svc in host.get("services", []):
            if svc.get("port") == req.port and (svc.get("protocol") or "tcp") == req.protocol:
                svc["ip"] = host.get("ip")

                svc["nvd"] = enrich_service_with_nvd(svc.get("product"), svc.get("version"))
                pcvp = pcvp_score_for_service(svc, exposure_effective)
                svc["pcvp_score"] = pcvp["pcvp_score"]
                svc["pcvp_level"] = pcvp["pcvp_level"]
                svc["pcvp_reasons"] = pcvp["pcvp_reasons"]

                target_svc = svc
                break

    if not target_svc:
        raise HTTPException(status_code=404, detail="Service not found for remediation generation")

    remediation = generate_remediation_openai(target_svc, exposure_effective)
    return {
        "scan_id": scan_id,
        "exposure": scan_status.exposure if scan_status else "auto",
        "service": target_svc,
        "remediation": remediation,
    }

@app.get("/scan/{scan_id}/report.pdf")
def download_report(scan_id: str):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    parsed = parse_nmap_xml(xml_path)

    scan_status = scan_status_store.get(scan_id)

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status and scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target) if scan_status else "external"
    )

    annotate_services_with_weak_creds(parsed)

    for host in parsed.get("hosts", []):
        for svc in host.get("services", []):
            svc["ip"] = host.get("ip")
            svc["nvd"] = enrich_service_with_nvd(svc.get("product"), svc.get("version"))
            pcvp = pcvp_score_for_service(svc, exposure_effective)
            svc["pcvp_score"] = pcvp["pcvp_score"]
            svc["pcvp_level"] = pcvp["pcvp_level"]
            svc["pcvp_reasons"] = pcvp["pcvp_reasons"]

    attack_graph = build_attack_graph(parsed)

    pdf_bytes = build_pdf_report(
        scan_id=scan_id,
        exposure=scan_status.exposure if scan_status else "auto",
        parsed=parsed,
        attack_graph=attack_graph,
    )

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="pcvp_report_{scan_id}.pdf"'},
    )