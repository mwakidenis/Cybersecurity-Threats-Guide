export const categories = [
  {
    id: "network-security",
    slug: "network-security",
    number: "01",
    title: "Network Security",
    subtitle: "Infrastructure Threats",
    icon: "🌐",
    color: "cyan",
    description:
      "Comprehensive coverage of network-layer attacks including traffic flooding, routing hijacks, and passive interception techniques used by adversaries to compromise infrastructure.",
    threats: [
      {
        id: "ddos",
        name: "DDoS Attacks",
        severity: "CRITICAL",
        description:
          "Distributed Denial-of-Service attacks overwhelm target servers with traffic from multiple compromised systems, rendering services unavailable.",
        detection: [
          "Monitor for sudden traffic spikes exceeding baseline thresholds",
          "Detect anomalous packet rate patterns using ddos_detection.py",
          "Analyze traffic fingerprints with traffic_analyzer.py",
        ],
        prevention: [
          "Implement rate limiting with configurable thresholds per IP",
          "Deploy upstream filtering and scrubbing services",
          "Configure firewall rules to block amplification vectors",
          "Use CDN-based DDoS protection layers",
        ],
        scripts: ["ddos_detection.py", "traffic_analyzer.py", "rate_limiting.py", "firewall_rules.txt"],
        cvss: "9.1",
      },
      {
        id: "mitm",
        name: "Man-in-the-Middle",
        severity: "HIGH",
        description:
          "MITM attacks intercept communications between two parties, enabling eavesdropping, data manipulation, and credential theft without either party's knowledge.",
        detection: [
          "Monitor ARP tables for suspicious changes via arp_spoof_detector.py",
          "Detect SSL stripping attempts with ssl_strip_detector.py",
          "Validate certificate chain integrity regularly",
        ],
        prevention: [
          "Enforce TLS 1.3 with strong cipher suites via ssl_tls_config.py",
          "Implement certificate pinning for mobile/API clients",
          "Enable HSTS with long max-age directives",
          "Use mutual TLS (mTLS) for service-to-service communication",
        ],
        scripts: ["arp_spoof_detector.py", "ssl_strip_detector.py", "ssl_tls_config.py", "certificate_pinning.py"],
        cvss: "7.4",
      },
      {
        id: "port-scan",
        name: "Port Scanning",
        severity: "MEDIUM",
        description:
          "Systematic probing of network ports to identify open services, operating systems, and potential attack surfaces for subsequent exploitation.",
        detection: [
          "Deploy IDS rules to flag sequential port probe patterns",
          "Detect SYN flood patterns with port_scan_detector.py",
          "Correlate firewall logs for reconnaissance indicators",
        ],
        prevention: [
          "Configure firewall to drop unsolicited connection attempts",
          "Enable stealth mode to suppress ICMP responses",
          "Use port knocking for sensitive service access",
          "Implement geofencing for administrative interfaces",
        ],
        scripts: ["port_scan_detector.py", "ids_rules.txt", "firewall_config.py", "stealth_mode.py"],
        cvss: "5.3",
      },
    ],
  },
  {
    id: "web-application-security",
    slug: "web-application-security",
    number: "02",
    title: "Web Application Security",
    subtitle: "Application Layer Attacks",
    icon: "💻",
    color: "green",
    description:
      "In-depth analysis of OWASP Top 10 vulnerabilities and application-layer exploits targeting web services, APIs, and user sessions in modern web stacks.",
    threats: [
      {
        id: "sqli",
        name: "SQL Injection",
        severity: "CRITICAL",
        description:
          "Injection of malicious SQL code into application queries, enabling unauthorized database access, data exfiltration, and in some cases, full server compromise.",
        detection: [
          "Scan endpoints with sql_injection_scanner.py for injection points",
          "Monitor database query logs for anomalous patterns",
          "Deploy WAF rules from waf_rules.txt to block payloads",
        ],
        prevention: [
          "Always use parameterized queries (see parameterized_queries.py)",
          "Validate and sanitize all user inputs strictly",
          "Apply principle of least privilege to DB accounts",
          "Enable stored procedure usage where possible",
        ],
        scripts: ["sql_injection_scanner.py", "waf_rules.txt", "parameterized_queries.py", "input_validation.py"],
        cvss: "9.8",
      },
      {
        id: "xss",
        name: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        description:
          "Injection of malicious scripts into web pages viewed by other users, enabling session hijacking, credential theft, and phishing within trusted contexts.",
        detection: [
          "Analyze page output with xss_detector.py for unencoded data",
          "Audit Content Security Policy headers via csp_analyzer.py",
          "Test reflected, stored, and DOM-based XSS vectors",
        ],
        prevention: [
          "Apply context-aware output encoding with output_encoding.py",
          "Configure strict Content Security Policy headers",
          "Use HttpOnly and Secure flags on all session cookies",
          "Implement Trusted Types API for DOM manipulation",
        ],
        scripts: ["xss_detector.py", "csp_analyzer.py", "output_encoding.py", "csp_headers.py"],
        cvss: "6.1",
      },
      {
        id: "csrf",
        name: "CSRF Attacks",
        severity: "HIGH",
        description:
          "Cross-Site Request Forgery tricks authenticated users into unknowingly submitting malicious requests, abusing their established session trust.",
        detection: [
          "Test CSRF token implementation with csrf_tester.py",
          "Analyze token entropy and binding with token_analyzer.py",
          "Audit Referer/Origin header validation logic",
        ],
        prevention: [
          "Implement synchronizer token pattern via csrf_protection.py",
          "Set SameSite=Strict on session cookies",
          "Validate Origin and Referer headers server-side",
          "Use custom request headers for AJAX endpoints",
        ],
        scripts: ["csrf_tester.py", "token_analyzer.py", "csrf_protection.py", "same_site_cookies.py"],
        cvss: "8.1",
      },
    ],
  },
  {
    id: "malware-analysis",
    slug: "malware-analysis",
    number: "03",
    title: "Malware Analysis",
    subtitle: "Malicious Software Threats",
    icon: "🦠",
    color: "red",
    description:
      "Deep-dive analysis of malware families including behavioral patterns, IOCs, evasion techniques, and automated detection mechanisms for ransomware, trojans, and rootkits.",
    threats: [
      {
        id: "ransomware",
        name: "Ransomware",
        severity: "CRITICAL",
        description:
          "Malware that encrypts victim data and demands payment for decryption keys, often spreading laterally across networks and causing millions in operational disruption.",
        detection: [
          "Monitor file system activity for mass encryption patterns",
          "Detect ransomware behavioral indicators with ransomware_behavior.py",
          "Watch for shadow copy deletion and backup tampering",
        ],
        prevention: [
          "Maintain offline 3-2-1 backups using backup_system.py",
          "Enforce application whitelisting via app_whitelisting.py",
          "Segment network to limit lateral movement",
          "Disable macro execution in Office documents",
        ],
        scripts: ["ransomware_behavior.py", "file_monitor.py", "backup_system.py", "app_whitelisting.py"],
        cvss: "9.3",
      },
      {
        id: "trojans",
        name: "Trojans",
        severity: "HIGH",
        description:
          "Malicious programs disguised as legitimate software that create backdoors, steal data, or serve as loaders for secondary malware payloads.",
        detection: [
          "Scan binaries with trojan_scanner.py for known signatures",
          "Analyze running processes with process_analyzer.py",
          "Monitor unusual network connections from trusted applications",
        ],
        prevention: [
          "Configure antivirus with behavioral detection via av_config.py",
          "Run untrusted applications in sandboxed environments",
          "Verify software integrity via cryptographic signatures",
          "Apply user privileges restrictions to limit damage scope",
        ],
        scripts: ["trojan_scanner.py", "process_analyzer.py", "av_config.py", "sandbox_setup.py"],
        cvss: "7.8",
      },
      {
        id: "rootkits",
        name: "Rootkits",
        severity: "CRITICAL",
        description:
          "Stealthy malware that hides deep within the OS kernel or firmware, granting persistent privileged access while actively concealing its presence from security tools.",
        detection: [
          "Perform integrity checks with integrity_checker.py",
          "Detect kernel-level anomalies using rootkit_detector.py",
          "Compare live memory against known-good baselines",
        ],
        prevention: [
          "Enable Secure Boot and UEFI signature validation",
          "Apply kernel patches and hardening via kernel_patching.py",
          "Use immutable infrastructure patterns where possible",
          "Enforce driver signing requirements on all platforms",
        ],
        scripts: ["rootkit_detector.py", "integrity_checker.py", "secure_boot.py", "kernel_patching.py"],
        cvss: "9.6",
      },
    ],
  },
  {
    id: "social-engineering",
    slug: "social-engineering",
    number: "04",
    title: "Social Engineering",
    subtitle: "Human-Factor Exploits",
    icon: "🎭",
    color: "yellow",
    description:
      "Analysis of psychological manipulation techniques used to bypass technical controls by exploiting human trust, authority bias, and urgency cues.",
    threats: [
      {
        id: "phishing",
        name: "Phishing",
        severity: "HIGH",
        description:
          "Deceptive communications impersonating trusted entities to trick recipients into revealing credentials, financial information, or installing malware.",
        detection: [
          "Analyze suspicious emails with phishing_detector.py",
          "Inspect headers and links using email_analyzer.py",
          "Check domain registration age and lookalike patterns",
        ],
        prevention: [
          "Configure SPF, DKIM, and DMARC email authentication",
          "Deploy email filters with ML-based phishing detection",
          "Conduct regular phishing simulation training",
          "Enable MFA on all user accounts to limit credential abuse",
        ],
        scripts: ["phishing_detector.py", "email_analyzer.py", "training_materials.md", "email_filters.py"],
        cvss: "8.0",
      },
      {
        id: "pretexting",
        name: "Pretexting",
        severity: "MEDIUM",
        description:
          "Fabrication of scenarios to manipulate targets into providing sensitive information or access, often via phone, email, or in-person interactions.",
        detection: [
          "Monitor for unusual access requests across channels",
          "Flag social engineering patterns with social_engineering_detector.py",
          "Review access logs for anomalous behavior post-contact",
        ],
        prevention: [
          "Establish and enforce identity verification procedures",
          "Define clear escalation paths for unusual requests",
          "Train staff on pretexting scripts and red flags",
          "Implement callback verification for sensitive actions",
        ],
        scripts: ["social_engineering_detector.py", "security_policy.md"],
        cvss: "6.5",
      },
    ],
  },
  {
    id: "cryptography",
    slug: "cryptography",
    number: "05",
    title: "Cryptography",
    subtitle: "Encryption & Key Management",
    icon: "🔐",
    color: "cyan",
    description:
      "Practical cryptographic implementations including symmetric/asymmetric encryption, secure hashing, digital signatures, and key management best practices.",
    threats: [
      {
        id: "weak-encryption",
        name: "Weak Encryption",
        severity: "HIGH",
        description:
          "Use of deprecated or insufficiently strong encryption algorithms exposing data to brute-force, known-plaintext, and side-channel attacks.",
        detection: [
          "Audit TLS configurations for weak cipher suites",
          "Scan codebase for hardcoded keys and weak algorithms",
          "Verify key lengths meet current NIST recommendations",
        ],
        prevention: [
          "Implement AES-256-GCM for symmetric encryption (aes_example.py)",
          "Use RSA-4096 or ECC for asymmetric operations (rsa_example.py)",
          "Enforce TLS 1.3 minimum across all endpoints",
          "Rotate keys according to defined lifecycle policies",
        ],
        scripts: ["aes_example.py", "rsa_example.py"],
        cvss: "7.5",
      },
      {
        id: "password-hashing",
        name: "Insecure Password Hashing",
        severity: "CRITICAL",
        description:
          "Storing passwords with weak or unsalted hashes enables mass credential recovery from stolen databases via rainbow tables or GPU-accelerated cracking.",
        detection: [
          "Audit password storage implementation in your stack",
          "Check for MD5/SHA1 usage in authentication flows",
          "Verify salt uniqueness and bcrypt/argon2 work factors",
        ],
        prevention: [
          "Use bcrypt or Argon2id via password_hashing.py",
          "Apply unique per-user salts automatically",
          "Set work factor tuned to ~100-300ms on target hardware",
          "Verify file integrity with integrity_checker.py",
        ],
        scripts: ["password_hashing.py", "integrity_checker.py"],
        cvss: "9.1",
      },
    ],
  },
  {
    id: "incident-response",
    slug: "incident-response",
    number: "06",
    title: "Incident Response",
    subtitle: "Detection, Containment & Recovery",
    icon: "🚨",
    color: "red",
    description:
      "Structured playbooks for digital forensics, threat containment, evidence preservation, and recovery procedures following a confirmed security incident.",
    threats: [
      {
        id: "forensics",
        name: "Digital Forensics",
        severity: "INFO",
        description:
          "Systematic collection, preservation, and analysis of digital evidence following a security incident to reconstruct events and support legal proceedings.",
        detection: [
          "Capture volatile memory before any system changes",
          "Analyze memory artifacts with memory_analyzer.py",
          "Perform disk forensics with disk_forensics.py",
        ],
        prevention: [
          "Establish evidence chain-of-custody procedures",
          "Pre-deploy logging and SIEM before incidents occur",
          "Define forensics runbooks for each system tier",
          "Train responders on evidence integrity preservation",
        ],
        scripts: ["memory_analyzer.py", "disk_forensics.py"],
        cvss: "N/A",
      },
      {
        id: "containment",
        name: "Containment & Recovery",
        severity: "CRITICAL",
        description:
          "Rapid isolation of compromised systems, threat eradication, and structured recovery procedures to minimize business impact during an active incident.",
        detection: [
          "Identify blast radius by analyzing lateral movement logs",
          "Map affected systems using network topology",
          "Verify integrity of backup sets before restoration",
        ],
        prevention: [
          "Execute network isolation with isolation_script.py",
          "Restore clean systems via backup_recovery.py",
          "Conduct post-incident review within 72 hours",
          "Update detection rules based on TTPs observed",
        ],
        scripts: ["isolation_script.py", "backup_recovery.py"],
        cvss: "N/A",
      },
    ],
  },
];

export const severityConfig = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.1)", label: "CRITICAL" },
  HIGH: { color: "#ff9500", bg: "rgba(255,149,0,0.1)", label: "HIGH" },
  MEDIUM: { color: "#ffd700", bg: "rgba(255,215,0,0.1)", label: "MEDIUM" },
  LOW: { color: "#00ff9d", bg: "rgba(0,255,157,0.1)", label: "LOW" },
  INFO: { color: "#00e5ff", bg: "rgba(0,229,255,0.1)", label: "INFO" },
};

export const stats = {
  totalSections: 6,
  totalTopics: "18+",
  pythonScripts: "45+",
  shellScripts: 2,
  docFiles: "18+",
};
