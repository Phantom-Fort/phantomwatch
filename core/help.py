import sys

def display_help():
    """Displays the help page with a brief introduction and a list of commands."""
    
    # ANSI escape codes for colors
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    help_text = f"""
    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────
                    PhantomWatch CLI - Interactive Shell
    ─────────────────────────────────────────────────────────────────────{RESET}

    {BLUE}PhantomWatch is a cybersecurity tool designed for threat detection, 
    incident response, and security analysis. It provides multiple modules 
    to assist security professionals in analyzing and mitigating threats.{RESET}

    {BOLD}Usage:{RESET}
      - In interactive mode, type commands directly.
      - Use '{GREEN}use <module>{RESET}' to choose a module and change the prompt.
      - Use '{GREEN}run{RESET}' to execute the selected module or '{GREEN}run <module>{RESET}' to run a specific one.

    {BOLD}{YELLOW}Available Commands:{RESET}
    ─────────────────────────────────────────────────────────────────────
    {GREEN}General Commands:{RESET}
      {BOLD}help{RESET}                           → Display this help page
      {BOLD}exit, quit{RESET}                     → Exit PhantomWatch interactive shell

    {GREEN}Module Management:{RESET}
      {BOLD}list-modules{RESET}                   → List all available modules
      {BOLD}use <module name>{RESET}              → Select a module (changes prompt)
      {BOLD}run{RESET}                            → Run the currently selected module
      {BOLD}run <module name>{RESET}              → Run a specific module
      {BOLD}phantomwatch -m <module>{RESET}       → Run a module using the CLI
      {BOLD}view-api{RESET}                       → View configured API keys
      

    {GREEN}Configuration:{RESET}
      {BOLD}set-api <SERVICE> <API_KEY>{RESET}    → Set API key for a specific service
      {BOLD}Example:{RESET} {RED}set-api VIRUSTOTAL 1234567890abcdef1234567890abcdef{RESET}

    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────
            Available Modules & Descriptions:{RESET}
Modules:
        1. Incident Response (`incident-response`)
          - Parses logs, analyzes system events, and runs automated response playbooks.
          - Tools: LogParser, Volatility
          - API: None
        
        2. SIEM Analysis (`siem-analysis`)
          - Correlates logs from multiple sources and applies Sigma rules for threat detection.
          - Tools: Elasticsearch, Sigma
          - API: ElasticSearch API
        
        3. Threat Intelligence (`threat-intel`)
          - Queries threat databases for malicious indicators (IPs, domains, files).
          - Tools: VirusTotal, AbuseIPDB
          - API: VirusTotal API, AbuseIPDB API
        
        4. YARA Scan (`yara-scan`)
          - Scans files and memory for malware using YARA rules.
          - Tools: YARA, HybridAnalysis
          - API: HybridAnalysis API
        
        5. Malware Analysis (`malware-analysis`)
          - Performs static and dynamic malware analysis.
          - Tools: ANY.RUN, HybridAnalysis
          - API: ANY.RUN API, HybridAnalysis API
        
        6. OSINT Recon (`osint-recon`)
          - Collects open-source intelligence on domains, emails, and infrastructure.
          - Tools: Shodan, Hunter.io
          - API: Shodan API, Hunter.io API
        
        7. Forensic Analysis (`forensic-analysis`)
          - Extracts forensic artifacts from disk images, memory dumps, and logs.
          - Tools: Autopsy, Volatility
          - API: None
        
        8. Web App Security (`websec-scanner`)
          - Scans web applications for vulnerabilities like XSS, SQLi, etc.
          - Tools: SecurityTrails, OWASP ZAP
          - API: SecurityTrails API
        
        9. Network Scanner (`network-scanner`)
          - Performs network reconnaissance, port scanning, and service enumeration.
          - Tools: Nmap, Masscan
          - API: None
        
        10. Exploit Finder (`exploit-finder`)
            - Searches for public exploits related to CVE IDs and software versions.
            - Tools: Exploit-DB
            - API: Exploit-DB API
        
        API Setup:
        Use the following command to set an API key for a module:
        ```
        set-api <SERVICE> <API_KEY>
        ```
        Example:
        ```
        set-api VIRUSTOTAL abc123xyz
        ```
        """ + f"""

    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────{RESET}
    {BOLD}Additional Information:{RESET}
      - Use {BOLD}'list-modules'{RESET} to see all available modules.
      - Ensure you have the correct API keys configured where necessary.
      - For more details, check the official PhantomWatch documentation.
    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────{RESET}
    """
    
    print(help_text)

if __name__ == "__main__":
    display_help()
