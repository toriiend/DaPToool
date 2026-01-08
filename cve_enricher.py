from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import json

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class CVEInfo:
    cve_id: str
    description: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    cvss_score: Optional[float]
    attack_vector: str
    exploit_available: bool
    affected_products: List[str]
    references: List[str]
    remediation: str


@dataclass
class AttackMethod:
    technique_id: str  # MITRE ATT&CK ID if available
    technique_name: str
    description: str
    detection_methods: List[str]
    mitigation_steps: List[str]


class CVEEnricher:
    """
    CVE Intelligence gathering WITHOUT requiring API keys
    Uses web scraping from public sources
    """
    
    def __init__(self, cache_timeout: int = 3600):
        self.cache: Dict[str, Any] = {}
        self.cache_timeout = cache_timeout
        self.session = None
        
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Security Research Tool)'
            })
    
    def enrich_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main entry point: enrich all findings with CVE + attack intel
        """
        if not REQUESTS_AVAILABLE:
            return {
                "error": "requests library not available",
                "enriched_findings": [],
                "cve_summary": {}
            }
        
        enriched = []
        cve_summary = {
            "total_cves_found": 0,
            "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "exploits_available": 0,
            "top_risks": []
        }
        
        for finding in findings:
            enriched_finding = self._enrich_single_finding(finding)
            enriched.append(enriched_finding)
            
            # Update summary
            if enriched_finding.get("cve_data"):
                for cve in enriched_finding["cve_data"]:
                    cve_summary["total_cves_found"] += 1
                    sev = cve.get("severity", "LOW")
                    cve_summary["severity_breakdown"][sev] = cve_summary["severity_breakdown"].get(sev, 0) + 1
                    if cve.get("exploit_available"):
                        cve_summary["exploits_available"] += 1
        
        # Identify top risks
        cve_summary["top_risks"] = self._identify_top_risks(enriched)
        
        return {
            "enriched_findings": enriched,
            "cve_summary": cve_summary,
            "attack_techniques": self._map_to_attack_techniques(findings)
        }
    
    def _enrich_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single finding with CVE data
        """
        enriched = finding.copy()
        
        # Extract potential CVE indicators from evidence
        evidence = finding.get("evidence", "")
        title = finding.get("title", "")
        
        # Search for CVE patterns
        cve_patterns = self._extract_cve_indicators(evidence, title)
        
        if cve_patterns:
            cve_data = []
            for pattern in cve_patterns[:3]:  # Limit to top 3 to avoid spam
                cve_info = self._fetch_cve_info(pattern)
                if cve_info:
                    cve_data.append(cve_info)
            
            enriched["cve_data"] = cve_data
        
        # Add attack methods based on OWASP category
        owasp_code = finding.get("owasp", "")
        enriched["attack_methods"] = self._get_attack_methods_for_owasp(owasp_code)
        
        # Enhanced remediation
        enriched["enhanced_remediation"] = self._generate_enhanced_remediation(finding, enriched.get("cve_data", []))
        
        return enriched
    
    def _extract_cve_indicators(self, evidence: str, title: str) -> List[str]:
        """
        Extract CVE IDs or technology indicators that might have CVEs
        """
        indicators = []
        
        # Direct CVE-ID pattern
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', evidence + " " + title, re.IGNORECASE)
        indicators.extend(cve_matches)
        
        # Technology/version patterns that commonly have CVEs
        tech_patterns = [
            (r'apache[/\s]+(\d+\.\d+)', 'apache'),
            (r'nginx[/\s]+(\d+\.\d+)', 'nginx'),
            (r'openssl[/\s]+(\d+\.\d+)', 'openssl'),
            (r'php[/\s]+(\d+\.\d+)', 'php'),
            (r'mysql[/\s]+(\d+\.\d+)', 'mysql'),
            (r'wordpress[/\s]+(\d+\.\d+)', 'wordpress'),
        ]
        
        for pattern, tech in tech_patterns:
            matches = re.findall(pattern, evidence.lower())
            if matches:
                indicators.append(f"{tech}_{matches[0]}")
        
        return indicators
    
    def _fetch_cve_info(self, indicator: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE info from public sources (without API key)
        Uses cve.mitre.org and other public databases
        """
        if not self.session:
            return None
        
        # Check cache
        cache_key = f"cve_{indicator}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached["timestamp"] < self.cache_timeout:
                return cached["data"]
        
        try:
            # If it's a direct CVE-ID
            if indicator.startswith("CVE-"):
                cve_data = self._scrape_cve_details(indicator)
                if cve_data:
                    self.cache[cache_key] = {"data": cve_data, "timestamp": time.time()}
                    return cve_data
            
            # If it's a technology indicator, search for recent CVEs
            else:
                recent_cves = self._search_technology_cves(indicator)
                if recent_cves:
                    self.cache[cache_key] = {"data": recent_cves[0], "timestamp": time.time()}
                    return recent_cves[0]
        
        except Exception as e:
            # Fail gracefully
            return {
                "cve_id": indicator,
                "description": f"Unable to fetch CVE details: {str(e)}",
                "severity": "UNKNOWN",
                "cvss_score": None,
                "attack_vector": "Unknown",
                "exploit_available": False,
                "affected_products": [],
                "references": [],
                "remediation": "Consult vendor security advisories"
            }
        
        return None
    
    def _scrape_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Scrape CVE details from public sources
        Note: This is a simplified version - production would need more robust parsing
        """
        if not self.session:
            return None
        
        try:
            # Try CVE.org (MITRE)
            url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                # Basic parsing (would need beautifulsoup for production)
                content = response.text
                
                # Extract description
                desc_match = re.search(r'<h2>Description</h2>\s*<div[^>]*>(.*?)</div>', content, re.DOTALL)
                description = desc_match.group(1).strip() if desc_match else "No description available"
                description = re.sub(r'<[^>]+>', '', description)  # Strip HTML tags
                
                return {
                    "cve_id": cve_id,
                    "description": description[:500],  # Limit length
                    "severity": self._estimate_severity_from_description(description),
                    "cvss_score": None,  # Would need NVD API for this
                    "attack_vector": "Network",  # Default assumption
                    "exploit_available": "exploit" in content.lower() or "poc" in content.lower(),
                    "affected_products": [],
                    "references": [url],
                    "remediation": "Apply vendor security patches immediately"
                }
        
        except Exception:
            pass
        
        return None
    
    def _search_technology_cves(self, tech_indicator: str) -> List[Dict[str, Any]]:
        """
        Search for CVEs related to a technology
        """
        # This would query vulnerability databases
        # For now, return a placeholder structure
        tech_name = tech_indicator.split('_')[0] if '_' in tech_indicator else tech_indicator
        
        return [{
            "cve_id": f"Related to {tech_name}",
            "description": f"Potential vulnerabilities detected in {tech_name}. Check vendor advisories.",
            "severity": "MEDIUM",
            "cvss_score": None,
            "attack_vector": "Network",
            "exploit_available": False,
            "affected_products": [tech_name],
            "references": [f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={tech_name}"],
            "remediation": f"Update {tech_name} to the latest stable version"
        }]
    
    def _estimate_severity_from_description(self, description: str) -> str:
        """
        Estimate severity based on keywords in description
        """
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['remote code execution', 'arbitrary code', 'rce', 'critical']):
            return "CRITICAL"
        elif any(word in desc_lower for word in ['sql injection', 'authentication bypass', 'privilege escalation']):
            return "HIGH"
        elif any(word in desc_lower for word in ['xss', 'csrf', 'information disclosure']):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_attack_methods_for_owasp(self, owasp_code: str) -> List[Dict[str, Any]]:
        """
        Map OWASP categories to common attack methods
        """
        attack_db = {
            "A01": [
                {
                    "name": "Path Traversal / Directory Traversal",
                    "description": "Attacker manipulates file paths to access unauthorized files",
                    "detection": ["Monitor for ../ patterns", "Log file access attempts", "Check for abnormal path requests"],
                    "mitigation": ["Implement strict input validation", "Use allowlists for file access", "Apply principle of least privilege"]
                },
                {
                    "name": "IDOR (Insecure Direct Object Reference)",
                    "description": "Direct access to objects without authorization checks",
                    "detection": ["Monitor for sequential ID enumeration", "Log access control failures"],
                    "mitigation": ["Implement proper access control checks", "Use indirect references", "Validate authorization on every request"]
                }
            ],
            "A02": [
                {
                    "name": "Weak Cipher Exploitation",
                    "description": "Exploit outdated or weak cryptographic algorithms",
                    "detection": ["Monitor TLS handshakes", "Check for deprecated protocols"],
                    "mitigation": ["Enforce TLS 1.3", "Disable weak ciphers", "Implement HSTS"]
                }
            ],
            "A03": [
                {
                    "name": "SQL Injection",
                    "description": "Inject malicious SQL code through input fields",
                    "detection": ["WAF alerts on SQL patterns", "Database error monitoring", "Query timing analysis"],
                    "mitigation": ["Use parameterized queries", "Implement ORM", "Apply input validation", "Use principle of least privilege for DB users"]
                },
                {
                    "name": "Command Injection",
                    "description": "Execute arbitrary system commands through vulnerable inputs",
                    "detection": ["Monitor for shell metacharacters", "Process execution logging"],
                    "mitigation": ["Avoid system calls with user input", "Use safe APIs", "Implement strict input validation"]
                }
            ],
            "A05": [
                {
                    "name": "Security Misconfiguration Exploitation",
                    "description": "Exploit default configs, verbose errors, open ports",
                    "detection": ["Regular security scans", "Configuration audits"],
                    "mitigation": ["Harden default configurations", "Disable unnecessary services", "Implement security headers"]
                }
            ],
            "A07": [
                {
                    "name": "Credential Stuffing",
                    "description": "Use stolen credentials from breaches to gain access",
                    "detection": ["Monitor failed login attempts", "Check for unusual login patterns"],
                    "mitigation": ["Implement MFA", "Use rate limiting", "Monitor for breached credentials"]
                },
                {
                    "name": "Session Hijacking",
                    "description": "Steal or predict session tokens",
                    "detection": ["Monitor for session anomalies", "Check for concurrent sessions"],
                    "mitigation": ["Use secure session management", "Implement session timeout", "Bind sessions to IP/User-Agent"]
                }
            ],
            "A10": [
                {
                    "name": "SSRF (Server-Side Request Forgery)",
                    "description": "Force server to make requests to internal resources",
                    "detection": ["Monitor outbound requests", "Check for internal IP access"],
                    "mitigation": ["Validate and sanitize URLs", "Use allowlists", "Block internal IP ranges"]
                }
            ]
        }
        
        return attack_db.get(owasp_code, [{
            "name": "Manual Security Review Required",
            "description": f"OWASP {owasp_code} vulnerabilities often require manual testing",
            "detection": ["Security code review", "Penetration testing"],
            "mitigation": ["Follow OWASP guidelines", "Implement defense-in-depth"]
        }])
    
    def _generate_enhanced_remediation(self, finding: Dict[str, Any], cve_data: List[Dict[str, Any]]) -> str:
        """
        Generate comprehensive remediation steps
        """
        steps = []
        
        # Original remediation
        original = finding.get("remediation", "")
        if original:
            steps.append(f"**Immediate Action**: {original}")
        
        # CVE-specific remediation
        if cve_data:
            steps.append("\n**CVE-Specific Actions**:")
            for cve in cve_data:
                steps.append(f"- {cve.get('cve_id', 'Unknown')}: {cve.get('remediation', 'No specific guidance')}")
        
        # Defense-in-depth recommendations
        steps.append("\n**Defense-in-Depth Measures**:")
        steps.append("- Implement network segmentation")
        steps.append("- Enable comprehensive logging and monitoring")
        steps.append("- Apply security patches regularly")
        steps.append("- Conduct regular security assessments")
        
        return "\n".join(steps)
    
    def _identify_top_risks(self, enriched_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify the most critical risks based on severity and exploitability
        """
        risks = []
        
        for finding in enriched_findings:
            cve_data = finding.get("cve_data", [])
            for cve in cve_data:
                severity = cve.get("severity", "LOW")
                exploit_available = cve.get("exploit_available", False)
                
                # Calculate risk score
                severity_score = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}.get(severity, 1)
                exploit_multiplier = 2 if exploit_available else 1
                risk_score = severity_score * exploit_multiplier
                
                risks.append({
                    "cve_id": cve.get("cve_id"),
                    "finding_title": finding.get("title"),
                    "severity": severity,
                    "exploit_available": exploit_available,
                    "risk_score": risk_score,
                    "description": cve.get("description", "")[:200]
                })
        
        # Sort by risk score and return top 5
        risks.sort(key=lambda x: x["risk_score"], reverse=True)
        return risks[:5]
    
    def _map_to_attack_techniques(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Map findings to MITRE ATT&CK techniques
        """
        # Simplified mapping - production would use proper ATT&CK framework
        mitre_mapping = {
            "A01": ["T1190 - Exploit Public-Facing Application", "T1083 - File and Directory Discovery"],
            "A02": ["T1040 - Network Sniffing", "T1557 - Man-in-the-Middle"],
            "A03": ["T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter"],
            "A05": ["T1190 - Exploit Public-Facing Application", "T1211 - Exploitation for Defense Evasion"],
            "A07": ["T1078 - Valid Accounts", "T1110 - Brute Force"],
            "A10": ["T1090 - Proxy", "T1071 - Application Layer Protocol"]
        }
        
        techniques = {}
        for finding in findings:
            owasp = finding.get("owasp", "")
            if owasp in mitre_mapping:
                techniques[owasp] = mitre_mapping[owasp]
        
        return techniques