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
    
    {BOLD}1️⃣ Incident Response {RESET}({GREEN}incident-response{RESET})
       {BLUE}- Assists in handling security incidents efficiently.{RESET}
       {BLUE}- Provides tools to analyze logs, detect intrusions, and respond to threats.{RESET}
       🔹 {RED}No API key required.{RESET}

    {BOLD}2️⃣ SIEM Correlation {RESET}({GREEN}siem-correlation{RESET})
       {BLUE}- Correlates logs and events from multiple sources to identify threats.{RESET}
       {BLUE}- Integrates with **ElasticSearch** for enhanced log analysis.{RESET}
       🔹 {YELLOW}Requires:{RESET} {BOLD}set-api ELASTICSEARCH <API_KEY>{RESET}

    {BOLD}3️⃣ Sigma Rules {RESET}({GREEN}sigma-rules{RESET})
       {BLUE}- Uses Sigma rules to detect security threats in log files.{RESET}
       {BLUE}- Converts Sigma rules into SIEM-specific formats.{RESET}
       🔹 {RED}No API key required.{RESET}

    {BOLD}4️⃣ Threat Intelligence {RESET}({GREEN}threat-intel{RESET})
       {BLUE}- Collects threat intelligence from multiple sources.{RESET}
       {BLUE}- Analyzes IPs, domains, and files for malicious activity.{RESET}
       🔹 {YELLOW}Requires:{RESET} 
         - {BOLD}set-api VIRUSTOTAL <API_KEY>{RESET} ({RED}VirusTotal{RESET})
         - {BOLD}set-api ABUSEIPDB <API_KEY>{RESET} ({RED}AbuseIPDB{RESET})

    {BOLD}5️⃣ YARA Scan {RESET}({GREEN}yara-scan{RESET})
       {BLUE}- Scans files and memory using **YARA** signatures.{RESET}
       {BLUE}- Helps detect malware, exploits, and suspicious activity.{RESET}
       🔹 {YELLOW}Requires:{RESET} {BOLD}set-api HYBRIDANALYSIS <API_KEY>{RESET} ({RED}HybridAnalysis{RESET})

    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────
    Additional Information:{RESET}
      - Use {BOLD}'list-modules'{RESET} to see all available modules.
      - Ensure you have the correct API keys configured where necessary.
      - For more details, check the official PhantomWatch documentation.
    {BOLD}{YELLOW}────────────────────────────────────────────────────────────────────{RESET}
    """
    
    print(help_text)

if __name__ == "__main__":
    display_help()
