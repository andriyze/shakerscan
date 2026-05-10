"""
Compliance Evidence Mapper Module

Maps security findings to major compliance frameworks:
- PCI DSS 4.0: Payment Card Industry Data Security Standard
- SOC 2: Trust Service Criteria (Security, Availability, Confidentiality)
- HIPAA: Health Insurance Portability and Accountability Act
- GDPR: General Data Protection Regulation (Article 32)
- CIS Controls v8: Center for Internet Security Controls
- NIST CSF: Cybersecurity Framework

Generates compliance-ready evidence reports for audit purposes.
"""

from datetime import UTC, datetime
from typing import Any

# ============================================================================
# COMPLIANCE FRAMEWORK MAPPINGS
# ============================================================================

# PCI DSS 4.0 Requirements
PCI_DSS_REQUIREMENTS = {
    "1.1": {
        "title": "Network Security Controls",
        "description": "Install and maintain network security controls",
        "checks": ["firewall", "network_segmentation", "access_control"]
    },
    "2.1": {
        "title": "Secure Configurations",
        "description": "Apply secure configurations to all system components",
        "checks": ["default_credentials", "unnecessary_services", "security_headers"]
    },
    "2.2": {
        "title": "Vendor Default Accounts",
        "description": "Change vendor-supplied defaults before installing",
        "checks": ["default_credentials", "default_passwords"]
    },
    "3.1": {
        "title": "Protect Stored Account Data",
        "description": "Protect stored account data",
        "checks": ["data_exposure", "encryption_at_rest"],
        "notes": "Encryption at rest cannot be verified via external scanning. This requirement requires internal audit and database configuration review."
    },
    "3.2": {
        "title": "Do Not Store Sensitive Authentication Data",
        "description": "Do not store sensitive authentication data after authorization",
        "checks": ["data_exposure", "credential_storage"],
        "notes": "Limited external visibility - can only detect exposed credentials, not storage practices"
    },
    "4.1": {
        "title": "Strong Cryptography for Transmission",
        "description": "Protect cardholder data with strong cryptography during transmission",
        "checks": ["tls_version", "cipher_strength", "starttls", "https_only"]
    },
    "4.2": {
        "title": "Secure Transmission Protocols",
        "description": "Use strong cryptography protocols",
        "checks": ["tls_1_2", "tls_1_3", "weak_ciphers", "ssl_deprecated"]
    },
    "5.1": {
        "title": "Anti-Malware Solutions",
        "description": "Protect systems against malware",
        "checks": ["malware_detection", "file_upload"]
    },
    "6.1": {
        "title": "Secure Development",
        "description": "Develop and maintain secure systems and software",
        "checks": ["vulnerable_components", "outdated_software", "cve_detection"]
    },
    "6.2": {
        "title": "Security Vulnerabilities",
        "description": "Address security vulnerabilities",
        "checks": ["xss", "sqli", "injection", "ssrf"]
    },
    "6.3": {
        "title": "Secure Application Development",
        "description": "Secure application development practices",
        "checks": ["csrf", "idor", "insecure_deserialization"]
    },
    "6.4": {
        "title": "Public-Facing Web Applications",
        "description": "Protect public-facing web applications",
        "checks": ["waf_detection", "security_headers", "csp"]
    },
    "6.5": {
        "title": "Common Coding Vulnerabilities",
        "description": "Address common coding vulnerabilities",
        "checks": ["owasp_top_10", "injection", "xss", "authentication"]
    },
    "7.1": {
        "title": "Restrict Access",
        "description": "Restrict access to system components",
        "checks": ["access_control", "forced_browsing", "authorization"]
    },
    "8.1": {
        "title": "Identify Users and Authenticate",
        "description": "Identify and authenticate access to system components",
        "checks": ["authentication", "session_management", "2fa"]
    },
    "8.2": {
        "title": "Strong Authentication",
        "description": "Establish strong authentication",
        "checks": ["password_policy", "rate_limiting", "brute_force"]
    },
    "8.3": {
        "title": "Secure Authentication",
        "description": "Secure authentication mechanisms",
        "checks": ["session_tokens", "cookie_security", "password_reset"]
    },
    "10.1": {
        "title": "Logging and Monitoring",
        "description": "Log and monitor access",
        "checks": ["logging", "audit_trail", "security_monitoring"]
    },
    "11.1": {
        "title": "Security Testing",
        "description": "Test security regularly",
        "checks": ["vulnerability_scanning", "penetration_testing"]
    },
    "11.3": {
        "title": "Vulnerability Management",
        "description": "External and internal vulnerability scans",
        "checks": ["vulnerability_scanning", "cve_detection"]
    },
    "12.1": {
        "title": "Information Security Policy",
        "description": "Establish information security policy",
        "checks": ["security_policy", "security_txt"]
    }
}

# SOC 2 Trust Service Criteria
SOC2_CRITERIA = {
    "CC1.1": {
        "title": "Control Environment",
        "category": "Security",
        "description": "Demonstrates commitment to integrity and ethical values",
        "checks": ["security_policy", "security_txt"]
    },
    "CC2.1": {
        "title": "Communication and Information",
        "category": "Security",
        "description": "Internal and external communication",
        "checks": ["security_headers", "disclosure"]
    },
    "CC3.1": {
        "title": "Risk Assessment",
        "category": "Security",
        "description": "Specifies suitable objectives",
        "checks": ["vulnerability_scanning", "risk_assessment"]
    },
    "CC3.2": {
        "title": "Risk Identification",
        "category": "Security",
        "description": "Identifies and analyzes risks",
        "checks": ["cve_detection", "vulnerability_assessment"]
    },
    "CC5.1": {
        "title": "Control Activities",
        "category": "Security",
        "description": "Selects and develops control activities",
        "checks": ["access_control", "security_headers"]
    },
    "CC5.2": {
        "title": "Technology Controls",
        "category": "Security",
        "description": "Selects and develops general controls over technology",
        "checks": ["tls_configuration", "encryption", "secure_protocols"]
    },
    "CC6.1": {
        "title": "Logical and Physical Access",
        "category": "Security",
        "description": "Implements logical access security software",
        "checks": ["authentication", "authorization", "access_control"]
    },
    "CC6.2": {
        "title": "User Registration and Authorization",
        "category": "Security",
        "description": "Prior to issuing system credentials",
        "checks": ["authentication", "session_management"]
    },
    "CC6.3": {
        "title": "User Credential Management",
        "category": "Security",
        "description": "Registers and authorizes new internal and external users",
        "checks": ["password_policy", "credential_management"]
    },
    "CC6.6": {
        "title": "Boundary Protection",
        "category": "Security",
        "description": "Restricts access from outside the system boundaries",
        "checks": ["firewall", "waf", "network_security"]
    },
    "CC6.7": {
        "title": "Data Transmission",
        "category": "Security",
        "description": "Restricts transmission of data to authorized users",
        "checks": ["tls_configuration", "encryption", "https"]
    },
    "CC6.8": {
        "title": "Malware Prevention",
        "category": "Security",
        "description": "Implements controls to prevent malware",
        "checks": ["malware_detection", "file_upload", "input_validation"]
    },
    "CC7.1": {
        "title": "Vulnerability Detection",
        "category": "Security",
        "description": "Detects and monitors security vulnerabilities",
        "checks": ["vulnerability_scanning", "monitoring"]
    },
    "CC7.2": {
        "title": "Security Anomalies",
        "category": "Security",
        "description": "Monitors system components for anomalies",
        "checks": ["monitoring", "logging", "alerting"]
    },
    "CC8.1": {
        "title": "Change Management",
        "category": "Security",
        "description": "Authorizes, designs, and develops changes",
        "checks": ["change_management", "version_control"]
    },
    "A1.1": {
        "title": "System Availability",
        "category": "Availability",
        "description": "Maintains, monitors, and evaluates current processing capacity and use",
        "checks": ["availability", "redundancy", "capacity", "uptime_monitoring", "load_balancing", "rate_limiting"],
        "notes": "External scanning can detect rate limiting, load balancing headers, and CDN/redundancy indicators"
    },
    "A1.2": {
        "title": "Recovery Capabilities",
        "category": "Availability",
        "description": "Environmental protections, backup, and recovery capabilities are maintained",
        "checks": ["disaster_recovery", "backup", "redundancy", "backup_detection", "failover"],
        "notes": "Limited external visibility - checks for backup file exposure and redundancy indicators"
    },
    "A1.3": {
        "title": "Recovery Testing",
        "category": "Availability",
        "description": "Recovery plan procedures are tested",
        "checks": ["recovery_testing"],
        "notes": "Cannot be verified via external scanning - requires internal audit"
    },
    "C1.1": {
        "title": "Confidential Information",
        "category": "Confidentiality",
        "description": "Identifies and maintains confidential information",
        "checks": ["data_classification", "encryption", "access_control"]
    },
    "C1.2": {
        "title": "Confidentiality Disposal",
        "category": "Confidentiality",
        "description": "Disposes of confidential information",
        "checks": ["data_disposal", "secure_deletion"]
    },
    "PI1.1": {
        "title": "Processing Integrity",
        "category": "Processing Integrity",
        "description": "Obtains or generates data to use",
        "checks": ["input_validation", "data_integrity"]
    },
    "P1.1": {
        "title": "Privacy Notice",
        "category": "Privacy",
        "description": "Provides notice about privacy practices",
        "checks": ["privacy_policy", "cookie_consent"]
    }
}

# HIPAA Security Rule Controls
HIPAA_CONTROLS = {
    "164.312(a)(1)": {
        "title": "Access Control",
        "description": "Implement technical policies for access control",
        "checks": ["authentication", "authorization", "access_control"]
    },
    "164.312(a)(2)(i)": {
        "title": "Unique User Identification",
        "description": "Assign unique name/number for tracking user identity",
        "checks": ["authentication", "session_management"]
    },
    "164.312(a)(2)(iii)": {
        "title": "Automatic Logoff",
        "description": "Terminate electronic session after inactivity",
        "checks": ["session_timeout", "session_management"]
    },
    "164.312(a)(2)(iv)": {
        "title": "Encryption and Decryption",
        "description": "Implement mechanism to encrypt and decrypt ePHI",
        "checks": ["encryption", "tls_configuration", "https"]
    },
    "164.312(b)": {
        "title": "Audit Controls",
        "description": "Implement mechanisms to record and examine access",
        "checks": ["logging", "audit_trail", "monitoring"]
    },
    "164.312(c)(1)": {
        "title": "Integrity",
        "description": "Protect ePHI from improper alteration or destruction",
        "checks": ["data_integrity", "input_validation"]
    },
    "164.312(d)": {
        "title": "Person or Entity Authentication",
        "description": "Verify person or entity seeking access",
        "checks": ["authentication", "2fa", "identity_verification"]
    },
    "164.312(e)(1)": {
        "title": "Transmission Security",
        "description": "Guard against unauthorized access during transmission",
        "checks": ["tls_configuration", "encryption", "https", "starttls"]
    },
    "164.312(e)(2)(i)": {
        "title": "Integrity Controls",
        "description": "Ensure ePHI is not improperly modified",
        "checks": ["data_integrity", "checksums", "validation"]
    },
    "164.312(e)(2)(ii)": {
        "title": "Encryption",
        "description": "Implement mechanism to encrypt ePHI when appropriate",
        "checks": ["encryption", "tls_configuration", "cipher_strength"]
    }
}

# GDPR Article 32 Technical Measures
GDPR_MEASURES = {
    "32.1.a": {
        "title": "Pseudonymisation and Encryption",
        "description": "Pseudonymisation and encryption of personal data",
        "checks": ["encryption", "tls_configuration", "data_protection"]
    },
    "32.1.b": {
        "title": "Confidentiality and Integrity",
        "description": "Ensure ongoing confidentiality, integrity, availability",
        "checks": ["access_control", "data_integrity", "availability"]
    },
    "32.1.c": {
        "title": "Resilience and Recovery",
        "description": "Ability to restore availability and access",
        "checks": ["backup", "disaster_recovery", "redundancy"]
    },
    "32.1.d": {
        "title": "Testing and Evaluation",
        "description": "Process for regularly testing and evaluating",
        "checks": ["vulnerability_scanning", "penetration_testing", "security_testing"]
    },
    "32.2": {
        "title": "Risk Assessment",
        "description": "Assess appropriate level of security",
        "checks": ["risk_assessment", "vulnerability_assessment"]
    }
}

# CIS Controls v8
CIS_CONTROLS = {
    "1": {
        "title": "Inventory and Control of Enterprise Assets",
        "description": "Actively manage all devices on the network",
        "checks": ["asset_inventory", "network_discovery"]
    },
    "2": {
        "title": "Inventory and Control of Software Assets",
        "description": "Actively manage all software on the network",
        "checks": ["software_inventory", "tech_fingerprint"]
    },
    "3": {
        "title": "Data Protection",
        "description": "Develop processes and controls to identify, classify, handle data",
        "checks": ["encryption", "data_classification", "access_control"]
    },
    "4": {
        "title": "Secure Configuration",
        "description": "Establish secure configurations for assets",
        "checks": ["security_headers", "tls_configuration", "default_credentials"]
    },
    "5": {
        "title": "Account Management",
        "description": "Manage credentials and access",
        "checks": ["authentication", "password_policy", "access_control"]
    },
    "6": {
        "title": "Access Control Management",
        "description": "Use processes to create, assign, manage credentials",
        "checks": ["authorization", "rbac", "least_privilege"]
    },
    "7": {
        "title": "Continuous Vulnerability Management",
        "description": "Develop plan to continuously assess vulnerabilities",
        "checks": ["vulnerability_scanning", "cve_detection", "patch_management"]
    },
    "8": {
        "title": "Audit Log Management",
        "description": "Collect, alert, review audit logs",
        "checks": ["logging", "monitoring", "audit_trail"]
    },
    "9": {
        "title": "Email and Web Browser Protections",
        "description": "Improve protections for email and web",
        "checks": ["email_security", "spf", "dmarc", "dkim"]
    },
    "10": {
        "title": "Malware Defenses",
        "description": "Prevent and control malware installations",
        "checks": ["malware_detection", "file_upload", "content_validation"]
    },
    "11": {
        "title": "Data Recovery",
        "description": "Establish and maintain data recovery practices",
        "checks": ["backup", "recovery", "redundancy"]
    },
    "12": {
        "title": "Network Infrastructure Management",
        "description": "Establish and maintain secure network infrastructure",
        "checks": ["network_security", "firewall", "segmentation"]
    },
    "13": {
        "title": "Network Monitoring and Defense",
        "description": "Operate processes to detect network threats",
        "checks": ["network_monitoring", "ids", "threat_detection"]
    },
    "14": {
        "title": "Security Awareness Training",
        "description": "Establish security awareness program",
        "checks": ["security_training", "phishing_awareness"]
    },
    "15": {
        "title": "Service Provider Management",
        "description": "Develop process to evaluate service providers",
        "checks": ["vendor_risk", "third_party_security"]
    },
    "16": {
        "title": "Application Software Security",
        "description": "Manage security lifecycle of software",
        "checks": ["secure_development", "vulnerability_testing", "code_review"]
    },
    "17": {
        "title": "Incident Response Management",
        "description": "Establish incident response program",
        "checks": ["incident_response", "security_txt", "contact_info"]
    },
    "18": {
        "title": "Penetration Testing",
        "description": "Test effectiveness of controls through pentesting",
        "checks": ["penetration_testing", "red_team", "security_testing"]
    }
}

# CWE to Check Type Mapping
CWE_CHECK_MAPPING = {
    "CWE-79": ["xss", "injection", "input_validation"],
    "CWE-89": ["sqli", "injection", "input_validation"],
    "CWE-200": ["data_exposure", "information_disclosure"],
    "CWE-284": ["access_control", "authorization"],
    "CWE-287": ["authentication", "session_management"],
    "CWE-295": ["tls_configuration", "certificate"],
    "CWE-306": ["authentication", "access_control"],
    "CWE-307": ["rate_limiting", "brute_force"],
    "CWE-311": ["encryption", "data_protection"],
    "CWE-319": ["tls_configuration", "https", "starttls"],
    "CWE-326": ["cipher_strength", "weak_crypto"],
    "CWE-327": ["cipher_strength", "weak_crypto"],
    "CWE-352": ["csrf", "session_management"],
    "CWE-434": ["file_upload", "content_validation"],
    "CWE-502": ["deserialization", "input_validation"],
    "CWE-522": ["credential_storage", "password_policy"],
    "CWE-523": ["https", "tls_configuration"],
    "CWE-601": ["open_redirect", "url_validation"],
    "CWE-611": ["xxe", "xml_security"],
    "CWE-614": ["cookie_security", "session_management"],
    "CWE-639": ["idor", "authorization"],
    "CWE-693": ["security_headers", "defense_in_depth"],
    "CWE-798": ["default_credentials", "hardcoded_secrets"],
    "CWE-918": ["ssrf", "input_validation"],
    "CWE-1104": ["vulnerable_components", "outdated_software"],
    "CWE-1188": ["insecure_defaults", "configuration"]
}

# OWASP Top 10 2021 Mapping
OWASP_TOP10_2021 = {
    "A01:2021": {
        "title": "Broken Access Control",
        "checks": ["access_control", "authorization", "idor", "forced_browsing"]
    },
    "A02:2021": {
        "title": "Cryptographic Failures",
        "checks": ["tls_configuration", "encryption", "cipher_strength", "https"]
    },
    "A03:2021": {
        "title": "Injection",
        "checks": ["xss", "sqli", "injection", "command_injection"]
    },
    "A04:2021": {
        "title": "Insecure Design",
        "checks": ["security_design", "threat_modeling"]
    },
    "A05:2021": {
        "title": "Security Misconfiguration",
        "checks": ["security_headers", "default_credentials", "configuration"]
    },
    "A06:2021": {
        "title": "Vulnerable and Outdated Components",
        "checks": ["vulnerable_components", "cve_detection", "outdated_software"]
    },
    "A07:2021": {
        "title": "Identification and Authentication Failures",
        "checks": ["authentication", "session_management", "password_policy"]
    },
    "A08:2021": {
        "title": "Software and Data Integrity Failures",
        "checks": ["deserialization", "data_integrity", "subresource_integrity"]
    },
    "A09:2021": {
        "title": "Security Logging and Monitoring Failures",
        "checks": ["logging", "monitoring", "audit_trail"]
    },
    "A10:2021": {
        "title": "Server-Side Request Forgery",
        "checks": ["ssrf", "url_validation"]
    }
}


# Evidence-first mappings used by the GRC matrix. These mappings are deliberately
# compact: they connect scanner-native signals to audit controls without implying
# that a black-box scan can prove full organizational compliance.
GRC_EVIDENCE_FRAMEWORKS = {
    "owasp_top10_2025": {
        "name": "OWASP Top 10:2025",
        "controls": {
            "A01:2025": {
                "title": "Broken Access Control",
                "checks": ["access_control", "authorization", "idor", "rbac", "least_privilege"],
                "owasp_prefixes": ["A01:"],
            },
            "A02:2025": {
                "title": "Cryptographic Failures",
                "checks": ["tls_configuration", "encryption", "cipher_strength", "weak_crypto", "https"],
                "owasp_prefixes": ["A02:"],
            },
            "A03:2025": {
                "title": "Injection",
                "checks": ["xss", "sqli", "injection", "command_injection", "input_validation"],
                "owasp_prefixes": ["A03:"],
            },
            "A05:2025": {
                "title": "Security Misconfiguration",
                "checks": ["security_headers", "configuration", "insecure_defaults", "cloud_security"],
                "owasp_prefixes": ["A05:"],
            },
            "A06:2025": {
                "title": "Vulnerable and Outdated Components",
                "checks": ["vulnerable_components", "outdated_software", "cve_detection"],
                "owasp_prefixes": ["A06:"],
            },
            "A08:2025": {
                "title": "Software and Data Integrity Failures",
                "checks": ["deserialization", "data_integrity", "subresource_integrity", "hardcoded_secrets"],
                "owasp_prefixes": ["A08:"],
            },
        },
    },
    "owasp_api_security": {
        "name": "OWASP API Security",
        "controls": {
            "API1": {
                "title": "Broken Object Level Authorization",
                "checks": ["idor", "authorization", "access_control"],
                "keywords": ["bola", "idor", "object level authorization"],
            },
            "API2": {
                "title": "Broken Authentication",
                "checks": ["authentication", "session_management", "session_tokens"],
                "keywords": ["jwt", "session", "token replay", "authentication"],
            },
            "API3": {
                "title": "Broken Object Property Level Authorization",
                "checks": ["authorization", "access_control", "api_security"],
                "keywords": ["property level", "field level", "mass assignment", "excessive data exposure"],
            },
            "API5": {
                "title": "Broken Function Level Authorization",
                "checks": ["authorization", "rbac", "least_privilege"],
                "keywords": ["function level", "privilege escalation", "admin"],
            },
            "API7": {
                "title": "Server-Side Request Forgery",
                "checks": ["ssrf", "url_validation"],
                "keywords": ["ssrf", "server-side request forgery"],
            },
            "API8": {
                "title": "Security Misconfiguration",
                "checks": ["security_headers", "configuration", "api_security"],
                "keywords": ["openapi", "cors", "misconfiguration"],
            },
            "API9": {
                "title": "Improper Inventory Management",
                "checks": ["asset_inventory", "api_security", "version_disclosure"],
                "keywords": ["undocumented", "deprecated api", "inventory", "shadow api"],
            },
        },
    },
    "owasp_llm_agentic": {
        "name": "OWASP LLM and Agentic AI",
        "controls": {
            "LLM01": {
                "title": "Prompt Injection",
                "checks": ["ai_security", "prompt_injection"],
                "owasp_prefixes": ["LLM01:"],
                "keywords": ["prompt injection", "jailbreak", "instruction override"],
            },
            "LLM02": {
                "title": "Sensitive Information Disclosure",
                "checks": ["ai_security"],
                "owasp_prefixes": ["LLM02:"],
                "keywords": ["system prompt", "secret", "tenant", "trace leak"],
            },
            "LLM05": {
                "title": "Improper Output Handling and RAG Integrity",
                "checks": ["ai_security", "rag_security"],
                "owasp_prefixes": ["LLM05:"],
                "keywords": ["rag", "corpus poisoning", "retrieval", "poisoning"],
            },
            "LLM07": {
                "title": "System Prompt Leakage",
                "checks": ["ai_security"],
                "owasp_prefixes": ["LLM07:"],
                "keywords": ["system prompt", "developer prompt"],
            },
            "LLM08": {
                "title": "Excessive Agency and Unsafe Tool Use",
                "checks": ["ai_security", "agentic_tool_use"],
                "owasp_prefixes": ["LLM08:"],
                "keywords": ["tool", "mcp", "oauth", "scope", "pkce", "local command", "approval"],
            },
            "LLM10": {
                "title": "Unbounded Consumption",
                "checks": ["ai_security"],
                "owasp_prefixes": ["LLM10:"],
                "keywords": ["cost abuse", "resource exhaustion", "token exhaustion"],
            },
        },
    },
    "nist_ai_rmf": {
        "name": "NIST AI RMF",
        "controls": {
            "GOVERN": {
                "title": "Govern AI Risk",
                "checks": ["ai_security"],
                "keywords": ["approval", "consent", "scope", "policy"],
            },
            "MAP": {
                "title": "Map Context and Exposure",
                "checks": ["ai_security"],
                "keywords": ["tenant", "data boundary", "tool inventory", "trace"],
            },
            "MEASURE": {
                "title": "Measure Model and System Behavior",
                "checks": ["ai_security"],
                "keywords": ["ai gate", "probe", "transcript", "judge"],
            },
            "MANAGE": {
                "title": "Manage AI Risk",
                "checks": ["ai_security"],
                "keywords": ["mcp", "rag", "cost abuse", "unsafe tool"],
            },
        },
    },
    "iso_27001_2022": {
        "name": "ISO/IEC 27001:2022",
        "controls": {
            "A.5.15": {
                "title": "Access Control",
                "checks": ["access_control", "authorization", "authentication"],
            },
            "A.5.19": {
                "title": "Information Security in Supplier Relationships",
                "checks": ["vendor_risk", "third_party_security", "subresource_integrity"],
            },
            "A.8.8": {
                "title": "Management of Technical Vulnerabilities",
                "checks": ["vulnerability_scanning", "cve_detection", "patch_management"],
            },
            "A.8.9": {
                "title": "Configuration Management",
                "checks": ["configuration", "security_headers", "insecure_defaults"],
            },
            "A.8.24": {
                "title": "Use of Cryptography",
                "checks": ["tls_configuration", "encryption", "cipher_strength", "weak_crypto"],
            },
            "A.8.28": {
                "title": "Secure Coding",
                "checks": ["xss", "sqli", "injection", "input_validation", "deserialization"],
            },
        },
    },
    "internal_sla": {
        "name": "Internal Risk SLA",
        "controls": {
            "SLA-CRITICAL": {
                "title": "Critical findings require immediate owner routing",
                "severities": ["critical"],
                "sla_hours": 24,
            },
            "SLA-HIGH": {
                "title": "High findings require near-term remediation",
                "severities": ["high"],
                "sla_hours": 72,
            },
            "SLA-MEDIUM": {
                "title": "Medium findings require planned remediation",
                "severities": ["medium"],
                "sla_hours": 720,
            },
        },
    },
}


# ============================================================================
# FINDING TO CHECK TYPE MAPPING
# ============================================================================

def _map_finding_to_check_types(finding: dict[str, Any]) -> set[str]:
    """Map a security finding to relevant check types."""
    check_types = set()

    # Map by CWE
    cwe = finding.get("cwe", "")
    if cwe in CWE_CHECK_MAPPING:
        check_types.update(CWE_CHECK_MAPPING[cwe])

    # Map by tool/category
    tool = finding.get("tool", "").lower()
    title = finding.get("title", "").lower()

    tool_mappings = {
        "tls": ["tls_configuration", "encryption", "cipher_strength", "https"],
        "ssl": ["tls_configuration", "encryption", "cipher_strength"],
        "cipher": ["cipher_strength", "encryption"],
        "header": ["security_headers"],
        "csp": ["csp", "security_headers"],
        "hsts": ["hsts", "security_headers", "https"],
        "cookie": ["cookie_security", "session_management"],
        "xss": ["xss", "injection", "input_validation"],
        "sqli": ["sqli", "injection", "input_validation"],
        "csrf": ["csrf", "session_management"],
        "ssrf": ["ssrf", "url_validation"],
        "idor": ["idor", "authorization", "access_control"],
        "auth": ["authentication", "session_management"],
        "session": ["session_management", "authentication"],
        "spf": ["email_security", "spf"],
        "dmarc": ["email_security", "dmarc"],
        "dkim": ["email_security", "dkim"],
        "dnssec": ["dns_security", "dnssec"],
        "smtp": ["email_security", "starttls"],
        "starttls": ["starttls", "encryption"],
        "certificate": ["certificate", "tls_configuration"],
        "ct_monitor": ["certificate", "ca_monitoring"],
        "nuclei": ["vulnerability_scanning", "cve_detection"],
        "default_cred": ["default_credentials", "authentication"],
        "upload": ["file_upload", "content_validation"],
        "redirect": ["open_redirect", "url_validation"],
        "traversal": ["path_traversal", "input_validation"],
        "deserialization": ["deserialization", "input_validation"],
        "rate": ["rate_limiting", "brute_force"],
        "2fa": ["2fa", "authentication"],
        "password": ["password_policy", "authentication"],
        "backup": ["backup_exposure", "data_exposure"],
        "cloud": ["cloud_security", "configuration"],
        "k8s": ["kubernetes", "container_security"],
        "docker": ["container_security", "configuration"],
        "secret": ["secret_exposure", "hardcoded_secrets"],
        "api": ["api_security", "authorization"],
        "version": ["version_disclosure", "information_disclosure"],
        "waf": ["waf", "network_security"],
        "dns": ["dns_security"],
        "mx": ["email_security", "redundancy"],
        "asn": ["network_security", "infrastructure"],
        "whois": ["domain_intel", "asset_inventory"],
    }

    for keyword, types in tool_mappings.items():
        if keyword in tool or keyword in title:
            check_types.update(types)

    # Map by severity (high/critical findings are security-critical)
    severity = finding.get("severity", "").lower()
    if severity in ["critical", "high"]:
        check_types.add("vulnerability_scanning")
        check_types.add("security_testing")

    return check_types


def _finding_text_blob(finding: dict[str, Any]) -> str:
    """Return a normalized text blob for keyword-based control mapping."""
    evidence = finding.get("evidence")
    parts = [
        finding.get("id"),
        finding.get("title"),
        finding.get("description"),
        finding.get("category"),
        finding.get("tool"),
        finding.get("type"),
        finding.get("source"),
        finding.get("owasp"),
        finding.get("cwe"),
        finding.get("url"),
        finding.get("endpoint"),
        evidence if isinstance(evidence, str) else None,
    ]
    if isinstance(evidence, dict):
        parts.extend(
            str(evidence.get(key, ""))
            for key in (
                "summary",
                "proof",
                "request",
                "response",
                "replay_command",
                "transcript",
                "business_impact",
                "remediation",
            )
        )
    return " ".join(str(part).lower() for part in parts if part)


def _finding_ref(finding: dict[str, Any]) -> str | None:
    """Stable display identifier for a finding in compliance evidence."""
    for key in ("id", "finding_id", "source_id"):
        value = finding.get(key)
        if value:
            return str(value)
    title = finding.get("title")
    url = finding.get("url") or finding.get("endpoint")
    if title and url:
        return f"{title} @ {url}"
    return str(title) if title else None


def _has_nested_value(value: Any, keys: tuple[str, ...]) -> bool:
    """Find whether any nested dict/list value has a populated key."""
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in keys and item:
                return True
            if _has_nested_value(item, keys):
                return True
    elif isinstance(value, list):
        return any(_has_nested_value(item, keys) for item in value)
    return False


def _finding_evidence_profile(finding: dict[str, Any]) -> dict[str, bool]:
    """Summarize whether the finding carries audit-grade proof artifacts."""
    evidence = finding.get("evidence")
    return {
        "proof_present": bool(
            finding.get("proof")
            or _has_nested_value(evidence, ("proof", "exploit_proof", "verification_proof", "artifacts"))
        ),
        "replay_available": bool(
            finding.get("replay_command")
            or _has_nested_value(evidence, ("replay_command", "curl", "request_replay"))
        ),
        "transcript_present": bool(
            finding.get("transcript")
            or _has_nested_value(evidence, ("transcript", "messages", "conversation"))
        ),
        "request_response_present": bool(
            finding.get("request")
            or finding.get("response")
            or _has_nested_value(evidence, ("request", "response", "raw_request", "raw_response"))
        ),
    }


def _finding_business_impact(finding: dict[str, Any]) -> str | None:
    """Extract business impact text when available."""
    for key in ("business_impact", "impact"):
        value = finding.get(key)
        if value:
            return str(value)
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        for key in ("business_impact", "impact"):
            value = evidence.get(key)
            if value:
                return str(value)
    severity = str(finding.get("severity", "")).lower()
    if severity == "critical":
        return "Potential material exposure or compromise path requiring immediate review."
    if severity == "high":
        return "Likely exploitable exposure requiring owner triage and remediation."
    return None


def _control_matches_finding(control: dict[str, Any], finding: dict[str, Any], check_types: set[str]) -> bool:
    """Return whether a GRC control should include this finding."""
    severity = str(finding.get("severity", "")).lower()
    if severity and severity in control.get("severities", []):
        return True

    if any(check in control.get("checks", []) for check in check_types):
        return True

    owasp = str(finding.get("owasp", ""))
    if any(owasp.startswith(prefix) or prefix in owasp for prefix in control.get("owasp_prefixes", [])):
        return True

    blob = _finding_text_blob(finding)
    return any(keyword in blob for keyword in control.get("keywords", []))


def _finding_evidence_item(finding: dict[str, Any]) -> dict[str, Any]:
    """Create a compact, audit-ready finding reference."""
    evidence_profile = _finding_evidence_profile(finding)
    return {
        "id": _finding_ref(finding),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "tool": finding.get("tool"),
        "source_type": finding.get("source_type") or finding.get("source"),
        "url": finding.get("url") or finding.get("endpoint"),
        "cwe": finding.get("cwe"),
        "owasp": finding.get("owasp"),
        "proof_present": evidence_profile["proof_present"],
        "replay_available": evidence_profile["replay_available"],
        "transcript_present": evidence_profile["transcript_present"],
        "request_response_present": evidence_profile["request_response_present"],
        "business_impact": _finding_business_impact(finding),
    }


def _control_evidence_requirements(control_id: str, control: dict[str, Any]) -> list[str]:
    """Return the proof artifacts expected for a control."""
    requirements = ["finding title", "severity", "affected URL or asset", "remediation guidance"]
    if control_id.startswith("LLM") or "ai" in " ".join(control.get("checks", [])).lower():
        requirements.extend(["probe transcript", "detector verdict", "AI judge rationale when configured"])
    if any(check in control.get("checks", []) for check in ("authorization", "access_control", "idor", "authentication")):
        requirements.extend(["authenticated request/response", "role or token context"])
    if any(check in control.get("checks", []) for check in ("xss", "sqli", "injection", "ssrf")):
        requirements.extend(["replay command", "exploit proof"])
    if any(check in control.get("checks", []) for check in ("tls_configuration", "encryption", "cipher_strength", "weak_crypto")):
        requirements.extend(["certificate or TLS evidence", "observed algorithm/cipher"])
    if "sla_hours" in control:
        requirements.extend(["owner", "first seen", "last seen", f"SLA target: {control['sla_hours']} hours"])
    return sorted(set(requirements))


def generate_grc_evidence_matrix(
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any],
    frameworks: list[str] | None = None
) -> dict[str, Any]:
    """Generate evidence-first framework mappings for audit and delta workflows."""
    selected_frameworks = frameworks or list(GRC_EVIDENCE_FRAMEWORKS.keys())
    matrix = {
        "frameworks": {},
        "summary": {
            "total_frameworks": 0,
            "total_controls": 0,
            "controls_with_findings": 0,
            "findings_with_proof": 0,
            "findings_with_replay": 0,
            "findings_with_transcript": 0,
            "findings_with_request_response": 0,
        },
        "evidence_quality": {
            "proof_coverage": 0.0,
            "replay_coverage": 0.0,
            "transcript_coverage": 0.0,
            "request_response_coverage": 0.0,
        },
        "scan_context": {
            "target": scan_results.get("target") or scan_results.get("url"),
            "scan_type": scan_results.get("scan_type"),
            "scan_id": scan_results.get("scan_id") or scan_results.get("id"),
        },
    }

    unique_findings: dict[str, dict[str, bool]] = {}

    for framework_key in selected_frameworks:
        framework = GRC_EVIDENCE_FRAMEWORKS.get(framework_key)
        if not framework:
            continue

        framework_result = {
            "name": framework["name"],
            "controls": {},
            "summary": {
                "total_controls": len(framework["controls"]),
                "controls_with_findings": 0,
                "total_findings": 0,
            },
        }

        for control_id, control in framework["controls"].items():
            control_findings = []
            for finding in findings:
                check_types = _map_finding_to_check_types(finding)
                if not _control_matches_finding(control, finding, check_types):
                    continue
                item = _finding_evidence_item(finding)
                control_findings.append(item)
                ref = item["id"] or f"{item.get('title')}:{item.get('url')}"
                unique_findings[ref] = {
                    "proof_present": item["proof_present"],
                    "replay_available": item["replay_available"],
                    "transcript_present": item["transcript_present"],
                    "request_response_present": item["request_response_present"],
                }

            if control_findings:
                framework_result["summary"]["controls_with_findings"] += 1
                framework_result["summary"]["total_findings"] += len(control_findings)

            framework_result["controls"][control_id] = {
                "title": control["title"],
                "findings": control_findings,
                "count": len(control_findings),
                "evidence_requirements": _control_evidence_requirements(control_id, control),
                **({"sla_hours": control["sla_hours"]} if "sla_hours" in control else {}),
            }

        matrix["frameworks"][framework_key] = framework_result
        matrix["summary"]["total_frameworks"] += 1
        matrix["summary"]["total_controls"] += framework_result["summary"]["total_controls"]
        matrix["summary"]["controls_with_findings"] += framework_result["summary"]["controls_with_findings"]

    denominator = max(len(unique_findings), 1)
    matrix["summary"]["findings_with_proof"] = sum(1 for item in unique_findings.values() if item["proof_present"])
    matrix["summary"]["findings_with_replay"] = sum(1 for item in unique_findings.values() if item["replay_available"])
    matrix["summary"]["findings_with_transcript"] = sum(1 for item in unique_findings.values() if item["transcript_present"])
    matrix["summary"]["findings_with_request_response"] = sum(1 for item in unique_findings.values() if item["request_response_present"])
    matrix["evidence_quality"]["proof_coverage"] = round(matrix["summary"]["findings_with_proof"] / denominator, 3)
    matrix["evidence_quality"]["replay_coverage"] = round(matrix["summary"]["findings_with_replay"] / denominator, 3)
    matrix["evidence_quality"]["transcript_coverage"] = round(matrix["summary"]["findings_with_transcript"] / denominator, 3)
    matrix["evidence_quality"]["request_response_coverage"] = round(
        matrix["summary"]["findings_with_request_response"] / denominator, 3
    )

    return matrix


# ============================================================================
# COMPLIANCE MAPPING FUNCTIONS
# ============================================================================

def map_to_pci_dss(findings: list[dict[str, Any]], scan_results: dict[str, Any]) -> dict[str, Any]:
    """Map findings to PCI DSS 4.0 requirements."""
    pci_report = {
        "framework": "PCI DSS 4.0",
        "requirements": {},
        "summary": {
            "total_requirements": len(PCI_DSS_REQUIREMENTS),
            "requirements_with_findings": 0,
            "passed": 0,
            "failed": 0,
            "not_assessed": 0
        },
        "critical_gaps": []
    }

    # Check each requirement
    for req_id, req_info in PCI_DSS_REQUIREMENTS.items():
        req_result = {
            "title": req_info["title"],
            "description": req_info["description"],
            "status": "not_assessed",
            "findings": [],
            "evidence": []
        }

        # Find related findings
        for finding in findings:
            check_types = _map_finding_to_check_types(finding)
            if any(check in req_info["checks"] for check in check_types):
                req_result["findings"].append({
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "cwe": finding.get("cwe")
                })

        # Determine status
        if req_result["findings"]:
            severities = [f.get("severity", "").lower() for f in req_result["findings"]]
            if "critical" in severities or "high" in severities:
                req_result["status"] = "failed"
                pci_report["summary"]["failed"] += 1
                pci_report["critical_gaps"].append({
                    "requirement": req_id,
                    "title": req_info["title"],
                    "severity": "high" if "high" in severities else "critical"
                })
            else:
                req_result["status"] = "warning"
                pci_report["summary"]["requirements_with_findings"] += 1
        else:
            # Check for positive evidence
            req_result["status"] = "passed"
            pci_report["summary"]["passed"] += 1

        pci_report["requirements"][req_id] = req_result

    pci_report["summary"]["not_assessed"] = (
        pci_report["summary"]["total_requirements"] -
        pci_report["summary"]["passed"] -
        pci_report["summary"]["failed"]
    )

    return pci_report


def map_to_soc2(findings: list[dict[str, Any]], scan_results: dict[str, Any]) -> dict[str, Any]:
    """Map findings to SOC 2 Trust Service Criteria."""
    soc2_report = {
        "framework": "SOC 2 Type II",
        "criteria": {},
        "categories": {
            "Security": {"passed": 0, "failed": 0, "total": 0},
            "Availability": {"passed": 0, "failed": 0, "total": 0},
            "Confidentiality": {"passed": 0, "failed": 0, "total": 0},
            "Processing Integrity": {"passed": 0, "failed": 0, "total": 0},
            "Privacy": {"passed": 0, "failed": 0, "total": 0}
        },
        "summary": {
            "total_criteria": len(SOC2_CRITERIA),
            "passed": 0,
            "failed": 0,
            "warnings": 0
        }
    }

    for criteria_id, criteria_info in SOC2_CRITERIA.items():
        criteria_result = {
            "title": criteria_info["title"],
            "category": criteria_info["category"],
            "description": criteria_info["description"],
            "status": "passed",
            "findings": [],
            "controls": []
        }

        # Find related findings
        for finding in findings:
            check_types = _map_finding_to_check_types(finding)
            if any(check in criteria_info["checks"] for check in check_types):
                criteria_result["findings"].append({
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "remediation": finding.get("remediation", finding.get("evidence", {}).get("remediation"))
                })

        # Determine status
        if criteria_result["findings"]:
            severities = [f.get("severity", "").lower() for f in criteria_result["findings"]]
            if "critical" in severities or "high" in severities:
                criteria_result["status"] = "failed"
                soc2_report["summary"]["failed"] += 1
                soc2_report["categories"][criteria_info["category"]]["failed"] += 1
            else:
                criteria_result["status"] = "warning"
                soc2_report["summary"]["warnings"] += 1
        else:
            soc2_report["summary"]["passed"] += 1
            soc2_report["categories"][criteria_info["category"]]["passed"] += 1

        soc2_report["categories"][criteria_info["category"]]["total"] += 1
        soc2_report["criteria"][criteria_id] = criteria_result

    return soc2_report


def map_to_hipaa(findings: list[dict[str, Any]], scan_results: dict[str, Any]) -> dict[str, Any]:
    """Map findings to HIPAA Security Rule controls."""
    hipaa_report = {
        "framework": "HIPAA Security Rule",
        "controls": {},
        "summary": {
            "total_controls": len(HIPAA_CONTROLS),
            "compliant": 0,
            "non_compliant": 0,
            "partial": 0
        },
        "risk_areas": []
    }

    for control_id, control_info in HIPAA_CONTROLS.items():
        control_result = {
            "title": control_info["title"],
            "description": control_info["description"],
            "status": "compliant",
            "findings": [],
            "risk_level": "low"
        }

        # Find related findings
        for finding in findings:
            check_types = _map_finding_to_check_types(finding)
            if any(check in control_info["checks"] for check in check_types):
                control_result["findings"].append({
                    "title": finding.get("title"),
                    "severity": finding.get("severity")
                })

        # Determine status
        if control_result["findings"]:
            severities = [f.get("severity", "").lower() for f in control_result["findings"]]
            if "critical" in severities:
                control_result["status"] = "non_compliant"
                control_result["risk_level"] = "critical"
                hipaa_report["summary"]["non_compliant"] += 1
                hipaa_report["risk_areas"].append({
                    "control": control_id,
                    "title": control_info["title"],
                    "risk": "critical"
                })
            elif "high" in severities:
                control_result["status"] = "non_compliant"
                control_result["risk_level"] = "high"
                hipaa_report["summary"]["non_compliant"] += 1
                hipaa_report["risk_areas"].append({
                    "control": control_id,
                    "title": control_info["title"],
                    "risk": "high"
                })
            else:
                control_result["status"] = "partial"
                control_result["risk_level"] = "medium"
                hipaa_report["summary"]["partial"] += 1
        else:
            hipaa_report["summary"]["compliant"] += 1

        hipaa_report["controls"][control_id] = control_result

    return hipaa_report


def map_to_gdpr(findings: list[dict[str, Any]], scan_results: dict[str, Any]) -> dict[str, Any]:
    """Map findings to GDPR Article 32 technical measures."""
    gdpr_report = {
        "framework": "GDPR Article 32",
        "measures": {},
        "summary": {
            "total_measures": len(GDPR_MEASURES),
            "implemented": 0,
            "gaps": 0,
            "partial": 0
        },
        "data_protection_issues": []
    }

    for measure_id, measure_info in GDPR_MEASURES.items():
        measure_result = {
            "title": measure_info["title"],
            "description": measure_info["description"],
            "status": "implemented",
            "findings": [],
            "gap_description": None
        }

        # Find related findings
        for finding in findings:
            check_types = _map_finding_to_check_types(finding)
            if any(check in measure_info["checks"] for check in check_types):
                measure_result["findings"].append({
                    "title": finding.get("title"),
                    "severity": finding.get("severity")
                })

        # Determine status
        if measure_result["findings"]:
            severities = [f.get("severity", "").lower() for f in measure_result["findings"]]
            if "critical" in severities or "high" in severities:
                measure_result["status"] = "gap"
                measure_result["gap_description"] = f"Critical security gap affecting {measure_info['title']}"
                gdpr_report["summary"]["gaps"] += 1
                gdpr_report["data_protection_issues"].append({
                    "article": measure_id,
                    "title": measure_info["title"],
                    "impact": "high"
                })
            else:
                measure_result["status"] = "partial"
                gdpr_report["summary"]["partial"] += 1
        else:
            gdpr_report["summary"]["implemented"] += 1

        gdpr_report["measures"][measure_id] = measure_result

    return gdpr_report


def map_to_cis_controls(findings: list[dict[str, Any]], scan_results: dict[str, Any]) -> dict[str, Any]:
    """Map findings to CIS Controls v8."""
    cis_report = {
        "framework": "CIS Controls v8",
        "controls": {},
        "summary": {
            "total_controls": len(CIS_CONTROLS),
            "implemented": 0,
            "partial": 0,
            "not_implemented": 0
        },
        "priority_actions": []
    }

    for control_id, control_info in CIS_CONTROLS.items():
        control_result = {
            "title": control_info["title"],
            "description": control_info["description"],
            "status": "implemented",
            "findings": [],
            "implementation_level": "full"
        }

        # Find related findings
        for finding in findings:
            check_types = _map_finding_to_check_types(finding)
            if any(check in control_info["checks"] for check in check_types):
                control_result["findings"].append({
                    "title": finding.get("title"),
                    "severity": finding.get("severity")
                })

        # Determine status
        if control_result["findings"]:
            severities = [f.get("severity", "").lower() for f in control_result["findings"]]
            if "critical" in severities or "high" in severities:
                control_result["status"] = "not_implemented"
                control_result["implementation_level"] = "none"
                cis_report["summary"]["not_implemented"] += 1
                cis_report["priority_actions"].append({
                    "control": control_id,
                    "title": control_info["title"],
                    "priority": "high"
                })
            else:
                control_result["status"] = "partial"
                control_result["implementation_level"] = "partial"
                cis_report["summary"]["partial"] += 1
        else:
            cis_report["summary"]["implemented"] += 1

        cis_report["controls"][control_id] = control_result

    return cis_report


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def generate_compliance_report(
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any],
    frameworks: list[str] | None = None
) -> dict[str, Any]:
    """
    Generate comprehensive compliance report mapping findings to frameworks.

    Args:
        findings: List of security findings from scan
        scan_results: Full scan results dictionary
        frameworks: List of frameworks to include (default: all)

    Returns:
        Dict with compliance mappings for each framework
    """
    if frameworks is None:
        frameworks = ["pci_dss", "soc2", "hipaa", "gdpr", "cis"]

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity", "").lower() == "critical"),
            "high": sum(1 for f in findings if f.get("severity", "").lower() == "high"),
            "medium": sum(1 for f in findings if f.get("severity", "").lower() == "medium"),
            "low": sum(1 for f in findings if f.get("severity", "").lower() == "low")
        },
        "frameworks": {},
        "owasp_mapping": _map_to_owasp(findings),
        "grc_evidence": generate_grc_evidence_matrix(findings, scan_results),
        "executive_summary": None,
        "remediation_priority": []
    }

    # Generate framework reports
    if "pci_dss" in frameworks:
        report["frameworks"]["pci_dss"] = map_to_pci_dss(findings, scan_results)

    if "soc2" in frameworks:
        report["frameworks"]["soc2"] = map_to_soc2(findings, scan_results)

    if "hipaa" in frameworks:
        report["frameworks"]["hipaa"] = map_to_hipaa(findings, scan_results)

    if "gdpr" in frameworks:
        report["frameworks"]["gdpr"] = map_to_gdpr(findings, scan_results)

    if "cis" in frameworks:
        report["frameworks"]["cis"] = map_to_cis_controls(findings, scan_results)

    # Generate executive summary
    report["executive_summary"] = _generate_executive_summary(report)

    # Generate prioritized remediation list
    report["remediation_priority"] = _generate_remediation_priority(findings, report)

    return report


def _map_to_owasp(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Map findings to OWASP Top 10 2021."""
    owasp_report = {
        "framework": "OWASP Top 10 2021",
        "categories": {}
    }

    for category_id, category_info in OWASP_TOP10_2021.items():
        category_result = {
            "title": category_info["title"],
            "findings": [],
            "count": 0
        }

        for finding in findings:
            owasp = finding.get("owasp", "")
            if category_id in owasp:
                category_result["findings"].append({
                    "title": finding.get("title"),
                    "severity": finding.get("severity")
                })
                category_result["count"] += 1

        owasp_report["categories"][category_id] = category_result

    return owasp_report


def _generate_executive_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Generate executive summary of compliance status."""
    summary = {
        "overall_status": "compliant",
        "risk_level": "low",
        "key_findings": [],
        "framework_status": {}
    }

    critical_count = report["scan_summary"]["critical"]
    high_count = report["scan_summary"]["high"]

    if critical_count > 0:
        summary["overall_status"] = "non_compliant"
        summary["risk_level"] = "critical"
    elif high_count > 0:
        summary["overall_status"] = "at_risk"
        summary["risk_level"] = "high"
    elif report["scan_summary"]["medium"] > 0:
        summary["overall_status"] = "needs_attention"
        summary["risk_level"] = "medium"

    # Summarize each framework
    for framework_name, framework_data in report.get("frameworks", {}).items():
        if framework_name == "pci_dss":
            summary["framework_status"]["PCI DSS 4.0"] = {
                "status": "non_compliant" if framework_data["summary"]["failed"] > 0 else "compliant",
                "gaps": framework_data["summary"]["failed"]
            }
        elif framework_name == "soc2":
            summary["framework_status"]["SOC 2"] = {
                "status": "non_compliant" if framework_data["summary"]["failed"] > 0 else "compliant",
                "gaps": framework_data["summary"]["failed"]
            }
        elif framework_name == "hipaa":
            summary["framework_status"]["HIPAA"] = {
                "status": "non_compliant" if framework_data["summary"]["non_compliant"] > 0 else "compliant",
                "gaps": framework_data["summary"]["non_compliant"]
            }
        elif framework_name == "gdpr":
            summary["framework_status"]["GDPR"] = {
                "status": "non_compliant" if framework_data["summary"]["gaps"] > 0 else "compliant",
                "gaps": framework_data["summary"]["gaps"]
            }
        elif framework_name == "cis":
            summary["framework_status"]["CIS Controls"] = {
                "status": "partial" if framework_data["summary"]["not_implemented"] > 0 else "implemented",
                "gaps": framework_data["summary"]["not_implemented"]
            }

    return summary


def _generate_remediation_priority(findings: list[dict[str, Any]], report: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate prioritized remediation list based on compliance impact."""
    priority_list = []

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in ["critical", "high", "medium"]:
            # Count framework impacts
            check_types = _map_finding_to_check_types(finding)
            framework_impact = 0
            impacted_frameworks = []

            for fw_name, fw_checks in [
                ("PCI DSS", [c for r in PCI_DSS_REQUIREMENTS.values() for c in r["checks"]]),
                ("SOC 2", [c for r in SOC2_CRITERIA.values() for c in r["checks"]]),
                ("HIPAA", [c for r in HIPAA_CONTROLS.values() for c in r["checks"]]),
                ("GDPR", [c for r in GDPR_MEASURES.values() for c in r["checks"]]),
                ("CIS", [c for r in CIS_CONTROLS.values() for c in r["checks"]])
            ]:
                if any(check in fw_checks for check in check_types):
                    framework_impact += 1
                    impacted_frameworks.append(fw_name)

            priority_list.append({
                "title": finding.get("title"),
                "severity": severity,
                "severity_score": severity_order.get(severity, 4),
                "framework_impact": framework_impact,
                "impacted_frameworks": impacted_frameworks,
                "cwe": finding.get("cwe"),
                "remediation": finding.get("remediation", finding.get("evidence", {}).get("remediation"))
            })

    # Sort by severity then framework impact
    priority_list.sort(key=lambda x: (x["severity_score"], -x["framework_impact"]))

    return priority_list[:20]  # Top 20 priority items
