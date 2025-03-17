# PhantomWatch

## Overview

PhantomWatch is a powerful security automation tool designed to streamline security operations, incident response, and threat intelligence analysis. It provides a modular approach, allowing cybersecurity professionals to integrate various tools and automate security workflows.

## Features

- **Modular Architecture**: Supports multiple security modules such as Incident Response, SIEM Correlation, Sigma Rules, Threat Intelligence, and YARA Scanning.
- **Database Integration**: Uses SQLite for storing configurations, logs, and results.
- **Configuration Management**: Utilizes `config.json` and `.env` for easy customization.
- **Command-Line Interface (CLI)**: Provides an interactive and easy-to-use interface for executing security commands.
- **Automated Installation**: Comes with an `install.sh` script for seamless setup.

## Installation

### Prerequisites

Ensure your system has the following installed:

- Python 3
- pip (Python package manager)
- SQLite3

### Steps

1. Clone the repository:

   ```sh
   git clone https://github.com/Phantom-Fort/phantomwatch.git
   cd phantomwatch
   ```

2. Run the installation script:

   ```sh
   chmod +x install.sh
   ./install.sh
   ```

3. Verify installation:

   ```sh
   phantomwatch --help
   ```

## Usage

### Listing Available Modules

```sh
phantomwatch list-modules
```

### Running a Module

```sh
phantomwatch run -m incident-response
```

### Viewing Help

```sh
phantomwatch --help
```

## Configuration

Modify `config/config.json` for custom settings. Sensitive credentials should be stored in `config/secrets.env`.

Example `config.json`:

```json
{
    "log_level": "info",
    "database_path": "database/phantomwatch.db"
}
```

Example `secrets.env`:

```ini
API_KEY=your_api_key_here
SECRET_KEY=your_secret_key_here
```

## Modules

### Incident Response
Parses logs, analyzes system events, and runs automated response playbooks.
- **Tools**: LogParser, Volatility
- **API**: None

### SIEM Analysis
Correlates logs from multiple sources and applies Sigma rules for threat detection.
- **Tools**: Elasticsearch, Sigma
- **API**: ElasticSearch API

### Threat Intelligence
Queries threat databases for malicious indicators (IPs, domains, files).
- **Tools**: VirusTotal, AbuseIPDB
- **API**: VirusTotal API, AbuseIPDB API

### YARA Scan
Scans files and memory for malware using YARA rules.
- **Tools**: YARA, HybridAnalysis
- **API**: HybridAnalysis API

### Malware Analysis
Performs static and dynamic malware analysis.
- **Tools**: ANY.RUN, HybridAnalysis
- **API**: ANY.RUN API, HybridAnalysis API

### OSINT Recon
Collects open-source intelligence on domains, emails, and infrastructure.
- **Tools**: Shodan, Hunter.io
- **API**: Shodan API, Hunter.io API

### Forensic Analysis
Extracts forensic artifacts from disk images, memory dumps, and logs.
- **Tools**: Autopsy, Volatility
- **API**: None

### Web App Security
Scans web applications for vulnerabilities like XSS, SQLi, etc.
- **Tools**: SecurityTrails, OWASP ZAP
- **API**: SecurityTrails API

### Network Scanner
Performs network reconnaissance, port scanning, and service enumeration.
- **Tools**: Nmap, Masscan
- **API**: None

### Exploit Finder
Searches for public exploits related to CVE IDs and software versions.
- **Tools**: Exploit-DB
- **API**: None

## API List

### Module
- **SIEM Analysis**: ElasticSearch API
- **Threat Intelligence**: VirusTotal API, MISP API, OTX API
- **YARA Scan**: HybridAnalysis API
- **Malware Analysis**: ANY.RUN API, HybridAnalysis API
- **OSINT Recon**: Shodan API, Hunter.io API
- **Web App Security**: SecurityTrails API

## Contributing

1. Fork the repository.
2. Create a new branch.
3. Make your changes and commit them.
4. Push your changes and submit a pull request.

## License

This project is licensed under the MIT License.

## Contact

For issues and inquiries, contact `posiayoola102@gmail.com` or open an issue on GitHub.