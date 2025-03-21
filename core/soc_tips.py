import random

def get_random_tips(num_tips=1):
    """Returns a list of random SOC and threat intelligence tips."""
    tips = [
        "Always verify logs for anomalies and suspicious patterns.",
        "Implement least privilege access to reduce attack surfaces.",
        "Regularly update and patch systems to mitigate vulnerabilities.",
        "Use multi-factor authentication (MFA) for enhanced security.",
        "Monitor threat intelligence feeds for emerging threats.",
        "Segment your network to limit the impact of potential breaches.",
        "Conduct regular security awareness training for employees.",
        "Ensure endpoint detection and response (EDR) solutions are in place.",
        "Utilize honeypots to detect and analyze potential attackers.",
        "Automate repetitive SOC tasks to improve efficiency."
        "Regularly review and update incident response plans.",
        "Encrypt sensitive data both in transit and at rest.",
        "Perform regular vulnerability assessments and penetration tests.",
        "Establish a baseline of normal network behavior.",
        "Implement robust email filtering to prevent phishing attacks.",
        "Use threat hunting to proactively identify potential threats.",
        "Ensure secure configurations for all devices and applications.",
        "Maintain an inventory of all hardware and software assets.",
        "Implement data loss prevention (DLP) solutions.",
        "Regularly back up critical data and verify the integrity of backups."
    ]
    return random.sample(tips, min(num_tips, len(tips)))

if __name__ == "__main__":
    for tip in get_random_tips(3):
        print(f"[+] SOC Tip: {tip}")
