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
      {BOLD}reports{RESET}                        → To view past results/reports
      {BOLD}logs{RESET}                           → To view past logs
      {BOLD}clear{RESET}                          → Clear the screen
      
    {GREEN}Module Management:{RESET}
      {BOLD}list{RESET}                           → List all available modules
      {BOLD}use <module name>{RESET}              → Select a module (changes prompt)
      {BOLD}run{RESET}                            → Run the currently selected module
      {BOLD}run <module name>{RESET}              → Run a specific module
      {BOLD}phantomwatch -m <module>{RESET}       → Run a module using the CLI
      {BOLD}view-api{RESET}                       → View all API keys
      {BOLD}back{RESET}                           → Go back to the main menu

        

    {GREEN}Configuration:{RESET}
      {BOLD}set-api <SERVICE> <API_KEY>{RESET}    → Set API key for a specific service
      {BOLD}Example:{RESET} {RED}set-api VIRUSTOTAL 1234567890abcdef1234567890abcdef{RESET}

    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────
    Available Modules & Descriptions:{RESET}

    {BOLD}Module{RESET}                {BOLD}Description{RESET}
    ─────────────────────────────────────────────────────────────────────
    {BOLD}Incident Response{RESET}     Parses logs, analyzes system events, and runs automated response playbooks.
                       Tools: LogParser, Volatility
                       API: None

    {BOLD}SIEM Analysis{RESET}         Correlates logs from multiple sources and applies Sigma rules for threat detection.
                       Tools: Elasticsearch, Sigma
                       API: ElasticSearch API

    {BOLD}Threat Intelligence{RESET}   Queries threat databases for malicious indicators (IPs, domains, files).
                       Tools: VirusTotal, MISP, OTX
                       API: VirusTotal API, MISP_URL, MISP API, OTX API

    {BOLD}YARA Scan{RESET}             Scans files and memory for malware using YARA rules.
                       Tools: YARA, HybridAnalysis
                       API: HybridAnalysis API

    {BOLD}Malware Analysis{RESET}      Performs static and dynamic malware analysis.
                       Tools: ANY.RUN, HybridAnalysis
                       API: ANY.RUN API, HybridAnalysis API

    {BOLD}OSINT Recon{RESET}           Collects open-source intelligence on domains, emails, and infrastructure.
                       Tools: Shodan, Hunter.io
                       API: Shodan API, Hunter.io API

    {BOLD}Forensic Analysis{RESET}     Extracts forensic artifacts from disk images, memory dumps, and logs.
                       Tools: Autopsy, Volatility
                       API: None

    {BOLD}Web App Security{RESET}      Scans web applications for vulnerabilities like XSS, SQLi, etc.
                       Tools: SecurityTrails, OWASP ZAP
                       API: SecurityTrails API

    {BOLD}Network Scanner{RESET}       Performs network reconnaissance, port scanning, and service enumeration.
                       Tools: Nmap, Masscan
                       API: None

    {BOLD}Exploit Finder{RESET}        Searches for public exploits related to CVE IDs and software versions.
                       Tools: Exploit-DB
                       API: None

    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────{RESET}
    {BOLD}API list:{RESET}
    ─────────────────────────────────────────────────────────────────────
    {BOLD}Module{RESET}                     {BOLD}Required API{RESET}
    ─────────────────────────────────────────────────────────────────────
    SIEM Analysis                      ElasticSearch API
    Threat Intelligence                VirusTotal API, MISP API, OTX API
    YARA Scan                          HybridAnalysis API
    Malware Analysis                   ANY.RUN API, HybridAnalysis API
    OSINT Recon                        Shodan API, Hunter.io API
    Web App Security                   SecurityTrails API

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
