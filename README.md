# PCVP — Privilege-Contextual Vulnerability Prioritizer

**A context-aware vulnerability assessment and prioritization tool that goes beyond traditional CVSS-only scoring.**

PCVP is a security assessment platform designed to help identify, analyze, and prioritize vulnerabilities based on their practical risk within a target environment. Instead of relying solely on generic vulnerability severity scores, PCVP combines vulnerability intelligence with contextual factors such as network exposure, exploitability, privilege impact, credential weaknesses, and potential attack paths.

The platform integrates network scanning, web directory enumeration, CVE enrichment, contextual risk scoring, interactive attack graph visualization, and AI-assisted remediation into a unified web interface.

## Key Features

* **Automated Network Scanning:** Uses Nmap to discover hosts, open ports, running services, service versions, and supported TCP, UDP, and OS detection options.
* **Web Directory Enumeration:** Integrates Gobuster to discover potentially exposed directories and web resources.
* **CVE Identification and Enrichment:** Maps detected services to relevant vulnerability information using CPE identifiers and the National Vulnerability Database (NVD) API 2.0.
* **Contextual Risk Scoring:** Combines vulnerability severity with exposure, exploitability, privilege impact, credential weaknesses, and attack-path relevance.
* **Privilege-Aware Analysis:** Considers the potential consequences of vulnerabilities involving ordinary user, administrator, or root-level privileges.
* **Weak Credential Detection:** Includes checks for weak credentials across supported services, including SSH, FTP, and HTTP, according to the configured assessment workflow.
* **Attack Graph Visualization:** Uses interactive graphs to represent relationships between hosts, protocols, services, and CVEs, helping analysts investigate potential attack paths and privilege escalation scenarios.
* **AI-Assisted Remediation:** Integrates Google Gemini to generate human-readable vulnerability explanations and suggested remediation steps.
* **AI Security Chatbot:** Provides a conversational interface for security-related questions using available scan context.
* **Interactive Dashboard:** Presents vulnerability findings, risk priorities, and assessment data in a centralized interface.
* **Persistent Scan History:** Uses SQLite to store supported application data and scan results.
* **Report Generation:** Supports reporting of assessment results and remediation information in the formats implemented by the application.

## Why Contextual Prioritization Matters

Traditional vulnerability management often relies heavily on CVSS severity scores. While CVSS provides a useful standardized measure of technical severity, it does not independently describe the full risk of a vulnerability in a particular environment.

For example, two vulnerabilities with similar severity scores may have very different practical implications:

* One affects a service that is reachable from the internet.
* Another affects a service isolated within an internal network.
* One may provide a path toward elevated privileges.
* Another may have limited impact and no identified relationship to other weaknesses.

PCVP is designed to consider this additional context and help analysts decide which findings deserve attention first.

## Contextual Risk Scoring

PCVP combines six major factors in its contextual prioritization model:

| Factor                | Purpose                                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| CVSS / Base Risk      | Provides standardized vulnerability severity information.                                                 |
| Exposure              | Considers whether the affected service is externally or internally accessible.                            |
| Exploitability        | Evaluates available exploitability information and the practical conditions associated with exploitation. |
| Privilege Impact      | Considers the privilege level and potential consequences of exploitation.                                 |
| Credential Weaknesses | Incorporates supported weak-credential or credential-related findings.                                    |
| Attack-Path Relevance | Considers the position of a finding within potential multi-step attack paths.                             |

The combined score is used to rank findings according to their contextual priority, helping security teams focus on risks that may have a greater impact on the environment.

**Important:** A contextual risk score is a prioritization aid, not proof that a vulnerability is exploitable. Results depend on the available scan evidence, vulnerability data, and scoring logic.

## Attack Graph Visualization

PCVP includes interactive attack graph visualization to help analysts understand the relationships between discovered assets and potential security weaknesses.

The graph represents relationships across elements such as:

* Hosts
* Network protocols
* Services
* CVEs
* Potential privilege escalation paths
* Possible vulnerability chains

This view helps analysts investigate how individual weaknesses may relate to broader attack scenarios rather than examining every finding in isolation.

Attack graph relationships should be treated as potential paths that require validation, not confirmation that a complete attack chain is exploitable.

## AI-Assisted Remediation

PCVP integrates Google Gemini to assist with understanding and addressing identified vulnerabilities.

The AI-assisted functionality is designed to provide:

* Plain-language explanations of security findings.
* Contextual descriptions of potential impact.
* Suggested remediation and mitigation steps.
* Assistance with security-related questions through the chatbot interface.

AI-generated output should be reviewed by a security professional before being used to make security decisions or applied to production systems.

## How It Works

The general assessment workflow is:

1. **Configure a target:** Enter an authorized target IP address, host, or CIDR range and select the relevant scan options.
2. **Discover assets and services:** Use Nmap to identify reachable hosts, ports, protocols, and services.
3. **Enumerate web resources:** Use Gobuster where applicable to discover directories and potentially exposed resources.
4. **Process scan results:** Parse scanner output into structured assessment data.
5. **Enrich vulnerability information:** Use service and CPE information to query the NVD API for relevant CVE records and severity information.
6. **Evaluate contextual risk:** Combine base severity with exposure, exploitability, privilege impact, credential-related findings, and attack-path relevance.
7. **Visualize relationships:** Present relevant host, service, and vulnerability relationships through the attack graph.
8. **Generate remediation guidance:** Use Google Gemini to assist with vulnerability explanations and suggested fixes.
9. **Review and retain results:** Display assessment data through the dashboard and store supported results in SQLite.

## Technology Stack

| Technology            | Role                                                         |
| --------------------- | ------------------------------------------------------------ |
| Python                | Backend implementation and assessment logic                  |
| FastAPI               | Backend API and application services                         |
| HTML, CSS, JavaScript | Frontend and interactive user interface                      |
| SQLite                | Persistent data storage and caching                          |
| Nmap                  | Network discovery and service scanning                       |
| Gobuster              | Web directory and resource enumeration                       |
| NVD API 2.0           | CVE and vulnerability information enrichment                 |
| CPE                   | Service and product identification for vulnerability mapping |
| Google Gemini         | AI-assisted remediation and chatbot functionality            |
| vis.js                | Interactive attack graph visualization                       |
| Chart.js              | Dashboard charts and analytics                               |

## Project Structure

The repository contains the backend, frontend, supporting scanning tools, wordlists, and Python dependency definitions.

```text
PCVP/
├── backend/
├── frontend/
├── gobuster_Windows_x86_64/
├── wordlists/
├── requirements.txt
├── llm_cache.json
└── README.md
```

The exact files and subdirectories may vary as the project evolves.

## Installation and Setup

### Prerequisites

Before running PCVP, ensure you have:

* Python installed at a version supported by the project dependencies.
* Git installed.
* Nmap installed and accessible to the application.
* Gobuster available for the supported web enumeration workflow.
* Internet connectivity for NVD API requests and other external services.
* A Google Gemini API key if using Gemini-powered functionality.

### 1. Clone the repository

```bash
git clone https://github.com/jzzzzjazzzz1/PCVP.git
cd PCVP
```

### 2. Create a virtual environment

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure external services

Configure the required API credentials and application settings according to the backend configuration.

For Google Gemini, provide your API key using the configuration mechanism supported by the application. Avoid placing API keys directly in source code or committing them to GitHub.

Verify that Nmap and Gobuster are installed and that their executable paths match the application's configuration.

### 5. Start the application

The backend and frontend are maintained in separate directories. Follow the entry points and startup instructions provided by the current implementation in `backend/` and `frontend/`.

Once the services are running, open the local application address configured by the project.

*The exact startup commands and local URL depend on the current backend and frontend configuration.*

## Example Use Case

Consider a target environment with multiple exposed services and several potential vulnerabilities.

A conventional scanner may return a long list of findings ordered primarily by severity. PCVP aims to provide additional context by helping the analyst investigate:

1. Which affected services are externally reachable?
2. Which vulnerabilities have relevant exploitability information?
3. Which findings may have a greater privilege impact?
4. Are there credential-related weaknesses that increase risk?
5. Could multiple findings form a potential attack path?
6. Which remediation actions should be prioritized?

This approach supports more informed vulnerability triage and remediation planning.

## Security and Responsible Use

PCVP is intended for authorized security testing, defensive security analysis, and research.

* Only scan systems you own or have explicit permission to assess.
* Confirm that target IP addresses and CIDR ranges are within the authorized scope.
* Understand the potential impact of active network and web scanning before running an assessment.
* Protect scan results because they may contain sensitive infrastructure information.
* Keep API keys, credentials, and other secrets out of source control.
* Validate AI-generated recommendations before applying them to real systems.

The tool supports vulnerability assessment and prioritization; its findings should not be interpreted as a guarantee that a system is secure or vulnerable.

## Limitations

* Vulnerability mapping depends on the accuracy of service identification and available NVD records.
* Not every detected service will have a reliably identifiable CVE.
* Network reachability, firewall rules, scan permissions, and tool configuration can affect discovery results.
* Contextual scores depend on the evidence and factors available to the application.
* Attack graphs may represent potential relationships rather than verified exploit chains.
* Weak-credential checks are limited to the services and methods supported by the implementation.
* AI-generated explanations may contain inaccuracies and require human review.
* External API availability and rate limits may affect vulnerability enrichment and AI functionality.

## Future Improvements

Potential enhancements include:

* Expanded vulnerability intelligence sources.
* More comprehensive attack-path analysis and validation.
* Additional scanning and service integrations.
* Improved contextual scoring explanations and evidence traceability.
* More flexible report export options and integrations with vulnerability management workflows.
* Expanded automated regression and integration testing.
* Additional safeguards for handling sensitive assessment data.

## License

Refer to the repository's license file for the applicable terms of use.

---

**PCVP — Turning vulnerability scan results into context-aware security priorities.**
