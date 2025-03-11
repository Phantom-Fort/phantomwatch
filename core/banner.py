def display_banner():
    # ANSI Escape Codes for Colors
    CYAN = "\033[96m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    banner = rf"""{RED}{BOLD}
─────────────────────────────────────────────────────────────────────

                          {CYAN}.-'      `-.  
                         /            \  
                        |              |  
                        |,  .-.  .-.  ,|  
                        | )(_o/  \o_)( |  
                        |/     /\     \|  
                        (_     ^^     _)  
                         \__|IIIIII|__/  
                          | \IIIIII/ |  
                           \        /  
                            `------`  

                        {YELLOW}☠️  PHANTOMWATCH ☠️  
                Automating SOC & Threat Intelligence{RESET}

─────────────────────────────────────────────────────────────────────
    """
    print(banner)

if __name__ == "__main__":
    display_banner()
