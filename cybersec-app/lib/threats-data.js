export const categories = [
  {
    id: "network-security",
    slug: "01-network-security",
    label: "01",
    title: "Network Security",
    icon: "⬡",
    color: "#00ff41",
    description:
      "Understand and defend against network-layer attacks targeting infrastructure, protocols, and communications.",
    threats: [
      {
        id: "ddos",
        title: "DDoS Attacks",
        severity: "CRITICAL",
        description:
          "Distributed Denial of Service attacks overwhelm target systems with traffic from multiple sources, rendering services unavailable.",
        detection: [
          "Monitor for sudden traffic spikes exceeding baseline thresholds",
          "Analyze traffic patterns for abnormal source distribution",
          "Use ddos_detection.py to track packet rates per interface",
          "Deploy traffic_analyzer.py for real-time flow inspection",
        ],
        prevention: [
          "Implement rate limiting via rate_limiting.py",
          "Configure upstream firewall rules (firewall_rules.txt)",
          "Use CDN-based traffic scrubbing services",
          "Deploy anycast network diffusion",
          "Set up SYN cookies to handle SYN flood attacks",
        ],
        scripts: ["ddos_detection.py", "traffic_analyzer.py", "rate_limiting.py"],
        tags: ["network", "availability", "infrastructure"],
      },
      {
        id: "mitm",
        title: "Man-in-the-Middle (MITM)",
        severity: "HIGH",
        description:
          "Attackers intercept communications between two parties, potentially eavesdropping or altering data in transit.",
        detection: [
          "Run arp_spoof_detector.py to identify ARP cache poisoning",
          "Use ssl_strip_detector.py to catch HTTPS downgrade attempts",
          "Monitor ARP tables for unexpected changes",
          "Inspect SSL certificate chains for anomalies",
        ],
        prevention: [
          "Enforce TLS 1.3 via ssl_tls_config.py",
          "Implement certificate pinning (certificate_pinning.py)",
          "Enable HSTS preloading across all domains",
          "Use mutual TLS (mTLS) for internal services",
        ],
        scripts: ["arp_spoof_detector.py", "ssl_strip_detector.py", "ssl_tls_config.py"],
        tags: ["network", "interception", "encryption"],
      },
      {
        id: "port-scanning",
        title: "Port Scanning",
        severity: "MEDIUM",
        description:
          "Reconnaissance technique used to discover open ports and services on a target host, often a precursor to exploitation.",
        detection: [
          "Deploy port_scan_detector.py on network ingress points",
          "Correlate IDS rules (ids_rules.txt) with log events",
          "Alert on connection attempts to closed/filtered ports",
        ],
        prevention: [
          "Use firewall_config.py to whitelist only necessary ports",
          "Enable stealth_mode.py to drop unsolicited probes",
          "Implement port knocking for sensitive services",
          "Use network segmentation to limit blast radius",
        ],
        scripts: ["port_scan_detector.py", "firewall_config.py", "stealth_mode.py"],
        tags: ["reconnaissance", "network", "firewall"],
      },
    ],
  },
  {
    id: "web-application-security",
    slug: "02-web-application-security",
    label: "02",
    title: "Web Application Security",
    icon: "◈",
    color: "#ff6b35",
    description:
      "Protect web applications from injection attacks, script exploits, and session manipulation vulnerabilities.",
    threats: [
      {
        id: "sql-injection",
        title: "SQL Injection",
        severity: "CRITICAL",
        description:
          "Attackers insert malicious SQL code into input fields to manipulate database queries and exfiltrate, modify, or destroy data.",
        detection: [
          "Run sql_injection_scanner.py against all input endpoints",
          "Deploy WAF rules from waf_rules.txt",
          "Monitor database error logs for unusual query structures",
          "Log and alert on SQL keywords in HTTP parameters",
        ],
        prevention: [
          "Use parameterized_queries.py for all DB interactions",
          "Enforce strict input_validation.py across forms",
          "Apply principle of least privilege to DB accounts",
          "Disable detailed database error messages in production",
        ],
        scripts: ["sql_injection_scanner.py", "parameterized_queries.py", "input_validation.py"],
        tags: ["injection", "database", "web"],
      },
      {
        id: "xss",
        title: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        description:
          "Malicious scripts are injected into trusted websites and executed in victims' browsers, enabling session theft and UI manipulation.",
        detection: [
          "Scan with xss_detector.py for reflected and stored XSS",
          "Audit CSP headers using csp_analyzer.py",
          "Review all user-supplied content rendered to HTML",
        ],
        prevention: [
          "Apply output_encoding.py before rendering user content",
          "Configure strict Content Security Policy (csp_headers.py)",
          "Enable HttpOnly and Secure flags on all cookies",
          "Use a sanitization library for rich text inputs",
        ],
        scripts: ["xss_detector.py", "csp_analyzer.py", "output_encoding.py"],
        tags: ["injection", "browser", "web"],
      },
      {
        id: "csrf",
        title: "Cross-Site Request Forgery (CSRF)",
        severity: "HIGH",
        description:
          "Tricks authenticated users into unknowingly submitting malicious requests to a web application they're logged into.",
        detection: [
          "Test with csrf_tester.py across state-changing endpoints",
          "Validate token integrity via token_analyzer.py",
          "Audit forms and AJAX calls for missing CSRF tokens",
        ],
        prevention: [
          "Integrate csrf_protection.py middleware on all POST routes",
          "Set SameSite=Strict via same_site_cookies.py",
          "Verify Origin and Referer headers server-side",
          "Use double-submit cookie pattern for APIs",
        ],
        scripts: ["csrf_tester.py", "csrf_protection.py", "same_site_cookies.py"],
        tags: ["session", "browser", "web"],
      },
    ],
  },
  {
    id: "malware-analysis",
    slug: "03-malware-analysis",
    label: "03",
    title: "Malware Analysis",
    icon: "◉",
    color: "#ff2d55",
    description:
      "Detect, analyze, and neutralize ransomware, trojans, rootkits, and other malicious software.",
    threats: [
      {
        id: "ransomware",
        title: "Ransomware",
        severity: "CRITICAL",
        description:
          "Malware that encrypts victim files and demands payment for decryption keys, crippling businesses and individuals.",
        detection: [
          "Monitor with ransomware_behavior.py for mass file encryption",
          "Use file_monitor.py to detect rapid file extension changes",
          "Alert on shadow copy deletion commands (vssadmin)",
          "Watch for unusual process spawning patterns",
        ],
        prevention: [
          "Automate backups with backup_system.py (3-2-1 rule)",
          "Enable app_whitelisting.py to block unauthorized executables",
          "Segment network to limit lateral movement",
          "Disable macros in Office documents by default",
        ],
        scripts: ["ransomware_behavior.py", "file_monitor.py", "backup_system.py"],
        tags: ["ransomware", "encryption", "malware"],
      },
      {
        id: "trojans",
        title: "Trojans",
        severity: "HIGH",
        description:
          "Malicious programs disguised as legitimate software that create backdoors, steal credentials, or drop additional payloads.",
        detection: [
          "Scan with trojan_scanner.py using signature and heuristic analysis",
          "Profile running processes via process_analyzer.py",
          "Detect unexpected outbound connections",
          "Check digital signatures on all executables",
        ],
        prevention: [
          "Configure av_config.py for real-time protection",
          "Deploy sandbox_setup.py for behavioral analysis",
          "Educate users to verify software authenticity",
          "Enforce code-signing policies organization-wide",
        ],
        scripts: ["trojan_scanner.py", "process_analyzer.py", "av_config.py"],
        tags: ["trojan", "backdoor", "malware"],
      },
      {
        id: "rootkits",
        title: "Rootkits",
        severity: "CRITICAL",
        description:
          "Stealthy malware that hides its presence and grants persistent privileged access to compromised systems.",
        detection: [
          "Run rootkit_detector.py for kernel-level anomaly detection",
          "Verify file integrity via integrity_checker.py",
          "Compare live system state to known-good baseline",
          "Use memory forensics to find hidden processes",
        ],
        prevention: [
          "Enforce Secure Boot via secure_boot.py configuration",
          "Apply kernel_patching.py to stay current on kernel CVEs",
          "Enable TPM-based attestation",
          "Use read-only root filesystems where possible",
        ],
        scripts: ["rootkit_detector.py", "integrity_checker.py", "secure_boot.py"],
        tags: ["rootkit", "stealth", "kernel"],
      },
    ],
  },
  {
    id: "social-engineering",
    slug: "04-social-engineering",
    label: "04",
    title: "Social Engineering",
    icon: "◎",
    color: "#bf5af2",
    description:
      "Recognize and counter human-manipulation tactics used to bypass technical security controls.",
    threats: [
      {
        id: "phishing",
        title: "Phishing",
        severity: "HIGH",
        description:
          "Deceptive emails, messages, or websites trick users into revealing credentials, financial information, or downloading malware.",
        detection: [
          "Scan emails with phishing_detector.py for suspicious indicators",
          "Analyze headers and links using email_analyzer.py",
          "Check sender domains against known phishing databases",
          "Flag lookalike domain names and Unicode homoglyphs",
        ],
        prevention: [
          "Train staff with training_materials.md simulations",
          "Configure email_filters.py with DMARC/DKIM/SPF enforcement",
          "Deploy browser-based phishing protection",
          "Implement MFA to limit credential compromise impact",
        ],
        scripts: ["phishing_detector.py", "email_analyzer.py", "email_filters.py"],
        tags: ["phishing", "email", "social"],
      },
      {
        id: "pretexting",
        title: "Pretexting",
        severity: "MEDIUM",
        description:
          "Attackers fabricate scenarios and false identities to extract sensitive information from employees or systems.",
        detection: [
          "Use social_engineering_detector.py to flag unusual access requests",
          "Log and review all privileged account usage",
          "Monitor for unusual data access patterns",
        ],
        prevention: [
          "Enforce security_policy.md identity verification procedures",
          "Establish call-back verification for sensitive requests",
          "Run regular social engineering awareness drills",
          "Implement need-to-know access controls",
        ],
        scripts: ["social_engineering_detector.py"],
        tags: ["pretexting", "identity", "social"],
      },
    ],
  },
  {
    id: "cryptography",
    slug: "05-cryptography",
    label: "05",
    title: "Cryptography",
    icon: "⬢",
    color: "#ffd60a",
    description:
      "Implement robust encryption, secure hashing, and key management to protect data at rest and in transit.",
    threats: [
      {
        id: "weak-encryption",
        title: "Weak Encryption",
        severity: "HIGH",
        description:
          "Use of outdated or misconfigured encryption algorithms exposes sensitive data to brute-force or cryptanalytic attacks.",
        detection: [
          "Audit cipher suites for deprecated algorithms (DES, RC4, MD5)",
          "Scan TLS configurations for weak key lengths",
          "Test certificate validity and chain integrity",
        ],
        prevention: [
          "Implement AES-256 using aes_example.py",
          "Use RSA-4096 or ECC via rsa_example.py",
          "Enforce TLS 1.3 minimum across all endpoints",
          "Rotate encryption keys on a regular schedule",
        ],
        scripts: ["aes_example.py", "rsa_example.py"],
        tags: ["encryption", "AES", "RSA"],
      },
      {
        id: "password-hashing",
        title: "Insecure Password Storage",
        severity: "CRITICAL",
        description:
          "Storing passwords in plaintext or with weak hashing allows mass credential compromise if databases are breached.",
        detection: [
          "Audit database schemas for plaintext or MD5/SHA1 passwords",
          "Check for unsalted hashes vulnerable to rainbow tables",
          "Review password reset flows for security weaknesses",
        ],
        prevention: [
          "Use password_hashing.py with bcrypt/Argon2id",
          "Apply per-user salts automatically",
          "Verify file integrity with integrity_checker.py",
          "Enforce minimum password complexity policies",
        ],
        scripts: ["password_hashing.py", "integrity_checker.py"],
        tags: ["hashing", "passwords", "storage"],
      },
    ],
  },
  {
    id: "incident-response",
    slug: "06-incident-response",
    label: "06",
    title: "Incident Response",
    icon: "◇",
    color: "#30d158",
    description:
      "Structured procedures for detecting, containing, eradicating, and recovering from security incidents.",
    threats: [
      {
        id: "digital-forensics",
        title: "Digital Forensics",
        severity: "INFO",
        description:
          "Systematic collection and analysis of digital evidence to understand the scope, timeline, and attribution of security incidents.",
        detection: [
          "Capture volatile memory with memory_analyzer.py before shutdown",
          "Perform disk imaging via disk_forensics.py (write-blocked)",
          "Preserve chain of custody for all evidence",
          "Correlate timestamps across systems and logs",
        ],
        prevention: [
          "Enable comprehensive centralized logging pre-incident",
          "Deploy endpoint detection and response (EDR) tools",
          "Maintain forensic readiness with baseline snapshots",
          "Document system configurations for comparison",
        ],
        scripts: ["memory_analyzer.py", "disk_forensics.py"],
        tags: ["forensics", "evidence", "analysis"],
      },
      {
        id: "containment",
        title: "Containment & Recovery",
        severity: "INFO",
        description:
          "Rapidly isolate compromised systems, eradicate threats, and restore services to minimize business impact.",
        detection: [
          "Identify breach scope using isolation_script.py network analysis",
          "Map lateral movement paths and compromised accounts",
          "Determine data exfiltration channels",
        ],
        prevention: [
          "Execute isolation_script.py to quarantine infected hosts",
          "Restore clean state from backup_recovery.py snapshots",
          "Conduct post-incident review and update runbooks",
          "Implement lessons learned into security controls",
        ],
        scripts: ["isolation_script.py", "backup_recovery.py"],
        tags: ["containment", "recovery", "IR"],
      },
    ],
  },
];

export const severityConfig = {
  CRITICAL: { label: "CRITICAL", bg: "#ff2d55", text: "#fff" },
  HIGH: { label: "HIGH", bg: "#ff9f0a", text: "#000" },
  MEDIUM: { label: "MED", bg: "#ffd60a", text: "#000" },
  LOW: { label: "LOW", bg: "#30d158", text: "#000" },
  INFO: { label: "INFO", bg: "#0a84ff", text: "#fff" },
};

export const stats = [
  { label: "Sections", value: "6" },
  { label: "Threats Covered", value: "18+" },
  { label: "Python Scripts", value: "45+" },
  { label: "Prevention Guides", value: "30+" },
];
