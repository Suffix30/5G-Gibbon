#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import socket
import subprocess
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ComplianceStandard(Enum):
    GSMA_5G = "GSMA 5G Security"
    NIST_CSF = "NIST Cybersecurity Framework"
    THREEGGPP = "3GPP TS 33.501"
    ISO27001 = "ISO 27001"
    CUSTOM = "Custom"


class CheckResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class AuditCheck:
    check_id: str
    name: str
    description: str
    category: str
    standard: ComplianceStandard
    severity: Severity
    result: CheckResult = CheckResult.SKIP
    details: str = ""
    remediation: str = ""
    evidence: Dict = field(default_factory=dict)


@dataclass
class AuditReport:
    timestamp: str
    target: str
    duration_seconds: float
    total_checks: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    errors: int
    score: float
    checks: List[AuditCheck] = field(default_factory=list)
    summary: str = ""


class Security5GAuditor:
    def __init__(self, target_network: str = "10.0.0.0/24"):
        self.target_network = target_network
        self.checks: List[AuditCheck] = []
        self.start_time: Optional[datetime] = None
        
    def _add_check(self, check: AuditCheck):
        self.checks.append(check)
        status_icon = {"PASS": "[OK]", "FAIL": "[X]", "WARNING": "[!]", "SKIP": "[-]", "ERROR": "[?]"}
        icon = status_icon.get(check.result.value, "[-]")
        logger.info(f"{icon} {check.check_id}: {check.name} - {check.result.value}")
        if check.result == CheckResult.FAIL:
            logger.warning(f"    Remediation: {check.remediation}")
    
    def run_full_audit(self, upf_ip: Optional[str] = None, amf_ip: Optional[str] = None, 
                       smf_ip: Optional[str] = None, nrf_ip: Optional[str] = None) -> AuditReport:
        self.start_time = datetime.now()
        self.checks = []
        
        logger.info("="*60)
        logger.info("5G SECURITY AUDIT")
        logger.info(f"Target Network: {self.target_network}")
        logger.info(f"Started: {self.start_time.isoformat()}")
        logger.info("="*60)
        
        logger.info("\n[1/6] Network Exposure Checks...")
        self._audit_network_exposure(upf_ip, amf_ip, smf_ip, nrf_ip)
        
        logger.info("\n[2/6] Protocol Security Checks...")
        self._audit_protocol_security(upf_ip, amf_ip, smf_ip)
        
        logger.info("\n[3/6] Authentication & Authorization...")
        self._audit_authentication(nrf_ip)
        
        logger.info("\n[4/6] Encryption & Key Management...")
        self._audit_encryption()
        
        logger.info("\n[5/6] DoS Protection Checks...")
        self._audit_dos_protection()
        
        logger.info("\n[6/6] Logging & Monitoring...")
        self._audit_logging()
        
        return self._generate_report()
    
    def _check_port_open(self, ip: str, port: int, protocol: str = "tcp") -> bool:
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _run_command(self, cmd: List[str]) -> Tuple[bool, str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)
    
    def _audit_network_exposure(self, upf_ip: Optional[str], amf_ip: Optional[str], smf_ip: Optional[str], nrf_ip: Optional[str]):
        if upf_ip:
            is_open = self._check_port_open(upf_ip, 2152, "udp")
            check = AuditCheck(
                check_id="NET-001",
                name="GTP-U Port Exposure",
                description="Check if GTP-U port (2152) is properly filtered",
                category="Network Exposure",
                standard=ComplianceStandard.GSMA_5G,
                severity=Severity.HIGH,
                result=CheckResult.FAIL if is_open else CheckResult.PASS,
                details=f"GTP-U port 2152 on {upf_ip}: {'OPEN' if is_open else 'FILTERED'}",
                remediation="Implement firewall rules to restrict GTP-U access to trusted gNodeBs only",
                evidence={"port": 2152, "ip": upf_ip, "open": is_open}
            )
            self._add_check(check)
        
        if smf_ip:
            is_open = self._check_port_open(smf_ip, 8805, "udp")
            check = AuditCheck(
                check_id="NET-002",
                name="PFCP Port Exposure",
                description="Check if PFCP port (8805) is properly filtered",
                category="Network Exposure",
                standard=ComplianceStandard.GSMA_5G,
                severity=Severity.HIGH,
                result=CheckResult.FAIL if is_open else CheckResult.PASS,
                details=f"PFCP port 8805 on {smf_ip}: {'OPEN' if is_open else 'FILTERED'}",
                remediation="Restrict PFCP access to control plane components only",
                evidence={"port": 8805, "ip": smf_ip, "open": is_open}
            )
            self._add_check(check)
        
        if amf_ip:
            is_open = self._check_port_open(amf_ip, 38412, "tcp")
            check = AuditCheck(
                check_id="NET-003",
                name="NGAP Port Exposure",
                description="Check if NGAP/SCTP port (38412) is properly filtered",
                category="Network Exposure",
                standard=ComplianceStandard.THREEGGPP,
                severity=Severity.CRITICAL,
                result=CheckResult.FAIL if is_open else CheckResult.PASS,
                details=f"NGAP port 38412 on {amf_ip}: {'OPEN' if is_open else 'FILTERED'}",
                remediation="Restrict NGAP access to authorized gNodeBs with IPsec",
                evidence={"port": 38412, "ip": amf_ip, "open": is_open}
            )
            self._add_check(check)
        
        if nrf_ip:
            is_open = self._check_port_open(nrf_ip, 7777, "tcp")
            check = AuditCheck(
                check_id="NET-004",
                name="SBI/NRF Port Exposure",
                description="Check if SBI port (7777) is properly secured",
                category="Network Exposure",
                standard=ComplianceStandard.THREEGGPP,
                severity=Severity.HIGH,
                result=CheckResult.WARNING if is_open else CheckResult.PASS,
                details=f"SBI port 7777 on {nrf_ip}: {'OPEN' if is_open else 'FILTERED'}",
                remediation="Implement mTLS for all SBI communications",
                evidence={"port": 7777, "ip": nrf_ip, "open": is_open}
            )
            self._add_check(check)
        
        mongodb_ports = [27017, 27018, 27019]
        for ip in [upf_ip, amf_ip, smf_ip, nrf_ip]:
            if ip:
                for port in mongodb_ports:
                    is_open = self._check_port_open(ip, port, "tcp")
                    if is_open:
                        check = AuditCheck(
                            check_id=f"NET-005-{ip}-{port}",
                            name="MongoDB Exposure",
                            description="Check if MongoDB is exposed",
                            category="Network Exposure",
                            standard=ComplianceStandard.NIST_CSF,
                            severity=Severity.CRITICAL,
                            result=CheckResult.FAIL,
                            details=f"MongoDB port {port} on {ip} is EXPOSED",
                            remediation="Restrict MongoDB to localhost or internal network with authentication",
                            evidence={"port": port, "ip": ip, "open": True}
                        )
                        self._add_check(check)
                        break
    
    def _audit_protocol_security(self, upf_ip: Optional[str], amf_ip: Optional[str], smf_ip: Optional[str]):
        check = AuditCheck(
            check_id="PROTO-001",
            name="GTP-U Header Validation",
            description="Check for GTP-U header validation implementation",
            category="Protocol Security",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.HIGH,
            result=CheckResult.WARNING,
            details="Manual verification required for GTP-U header validation",
            remediation="Implement strict GTP-U header parsing and validation"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="PROTO-002",
            name="TEID Randomization",
            description="Check if TEIDs are randomly generated",
            category="Protocol Security",
            standard=ComplianceStandard.GSMA_5G,
            severity=Severity.MEDIUM,
            result=CheckResult.WARNING,
            details="Manual verification required for TEID randomization",
            remediation="Use cryptographically random TEID generation"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="PROTO-003",
            name="PFCP Sequence Number Validation",
            description="Check for PFCP sequence number validation",
            category="Protocol Security",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.MEDIUM,
            result=CheckResult.WARNING,
            details="Manual verification required for sequence validation",
            remediation="Implement strict PFCP sequence number checking"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="PROTO-004",
            name="NAS Message Integrity",
            description="Check NAS message integrity protection",
            category="Protocol Security",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.CRITICAL,
            result=CheckResult.WARNING,
            details="Verify NIA (NAS Integrity Algorithm) implementation",
            remediation="Ensure NIA2 (128-bit) or stronger is used"
        )
        self._add_check(check)
    
    def _audit_authentication(self, nrf_ip: Optional[str]):
        check = AuditCheck(
            check_id="AUTH-001",
            name="5G-AKA Implementation",
            description="Verify 5G-AKA authentication is implemented",
            category="Authentication",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.CRITICAL,
            result=CheckResult.WARNING,
            details="Manual verification of 5G-AKA implementation required",
            remediation="Ensure full 5G-AKA with SUCI privacy protection"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="AUTH-002",
            name="NF OAuth 2.0",
            description="Check NF-to-NF OAuth 2.0 authentication",
            category="Authentication",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.HIGH,
            result=CheckResult.WARNING,
            details="Verify SBI OAuth 2.0 token-based authentication",
            remediation="Implement OAuth 2.0 for all SBI interfaces"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="AUTH-003",
            name="gNodeB Authentication",
            description="Verify gNodeB mutual authentication",
            category="Authentication",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.CRITICAL,
            result=CheckResult.WARNING,
            details="Check for certificate-based gNodeB authentication",
            remediation="Implement PKI-based gNodeB authentication with IPsec"
        )
        self._add_check(check)
    
    def _audit_encryption(self):
        check = AuditCheck(
            check_id="ENC-001",
            name="User Plane Encryption",
            description="Check user plane encryption (NEA algorithms)",
            category="Encryption",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.HIGH,
            result=CheckResult.WARNING,
            details="Verify NEA1/NEA2/NEA3 implementation for user plane",
            remediation="Ensure NEA2 (128-bit AES) or NEA3 (128-bit SNOW) is used"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="ENC-002",
            name="Control Plane Encryption",
            description="Check control plane encryption",
            category="Encryption",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.CRITICAL,
            result=CheckResult.WARNING,
            details="Verify NAS and RRC encryption implementation",
            remediation="Ensure 128-bit encryption for all signaling"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="ENC-003",
            name="TLS for SBI",
            description="Check TLS 1.3 for SBI interfaces",
            category="Encryption",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.HIGH,
            result=CheckResult.WARNING,
            details="Verify TLS 1.3 with strong cipher suites for SBI",
            remediation="Implement TLS 1.3 with mTLS for all NF communications"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="ENC-004",
            name="Key Derivation Security",
            description="Check key hierarchy implementation",
            category="Encryption",
            standard=ComplianceStandard.THREEGGPP,
            severity=Severity.CRITICAL,
            result=CheckResult.WARNING,
            details="Verify K -> K_AMF -> K_gNB -> K_RRC/K_UP derivation",
            remediation="Ensure proper key separation and no key reuse"
        )
        self._add_check(check)
    
    def _audit_dos_protection(self):
        _, output = self._run_command(["iptables", "-L", "-n"])
        has_rate_limit = "hashlimit" in output.lower() or "limit" in output.lower()
        
        check = AuditCheck(
            check_id="DOS-001",
            name="GTP-U Rate Limiting",
            description="Check for GTP-U rate limiting rules",
            category="DoS Protection",
            standard=ComplianceStandard.GSMA_5G,
            severity=Severity.HIGH,
            result=CheckResult.PASS if has_rate_limit else CheckResult.FAIL,
            details=f"Rate limiting rules: {'FOUND' if has_rate_limit else 'NOT FOUND'}",
            remediation="Implement iptables/nftables rate limiting for GTP-U traffic"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="DOS-002",
            name="SCTP INIT Flood Protection",
            description="Check for SCTP INIT flood protection",
            category="DoS Protection",
            standard=ComplianceStandard.NIST_CSF,
            severity=Severity.HIGH,
            result=CheckResult.WARNING,
            details="Verify SCTP INIT rate limiting and cookie protection",
            remediation="Enable SCTP cookie validation and INIT rate limiting"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="DOS-003",
            name="SBI Request Throttling",
            description="Check for API rate limiting on SBI",
            category="DoS Protection",
            standard=ComplianceStandard.NIST_CSF,
            severity=Severity.MEDIUM,
            result=CheckResult.WARNING,
            details="Verify SBI API rate limiting implementation",
            remediation="Implement API gateway with request throttling"
        )
        self._add_check(check)
    
    def _audit_logging(self):
        log_paths = ["/var/log/amf", "/var/log/smf", "/var/log/upf", "/var/log/5gc"]
        logs_exist = any(os.path.exists(p) for p in log_paths)
        
        check = AuditCheck(
            check_id="LOG-001",
            name="Security Event Logging",
            description="Check for comprehensive security logging",
            category="Logging & Monitoring",
            standard=ComplianceStandard.ISO27001,
            severity=Severity.HIGH,
            result=CheckResult.PASS if logs_exist else CheckResult.WARNING,
            details=f"5G component logs: {'FOUND' if logs_exist else 'NOT FOUND in standard paths'}",
            remediation="Implement centralized logging with security event correlation"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="LOG-002",
            name="Authentication Failure Logging",
            description="Check for auth failure logging",
            category="Logging & Monitoring",
            standard=ComplianceStandard.NIST_CSF,
            severity=Severity.HIGH,
            result=CheckResult.WARNING,
            details="Verify authentication failures are logged with source info",
            remediation="Log all auth failures with UE/gNB identifiers"
        )
        self._add_check(check)
        
        check = AuditCheck(
            check_id="LOG-003",
            name="Anomaly Detection",
            description="Check for anomaly detection systems",
            category="Logging & Monitoring",
            standard=ComplianceStandard.NIST_CSF,
            severity=Severity.MEDIUM,
            result=CheckResult.WARNING,
            details="Verify network anomaly detection implementation",
            remediation="Deploy 5G-aware IDS/IPS with protocol-specific signatures"
        )
        self._add_check(check)
    
    def _generate_report(self) -> AuditReport:
        end_time = datetime.now()
        start = self.start_time or end_time
        duration = (end_time - start).total_seconds()
        
        passed = sum(1 for c in self.checks if c.result == CheckResult.PASS)
        failed = sum(1 for c in self.checks if c.result == CheckResult.FAIL)
        warnings = sum(1 for c in self.checks if c.result == CheckResult.WARNING)
        skipped = sum(1 for c in self.checks if c.result == CheckResult.SKIP)
        errors = sum(1 for c in self.checks if c.result == CheckResult.ERROR)
        
        total = len(self.checks)
        score = (passed / total * 100) if total > 0 else 0
        
        if failed > 0:
            grade = "CRITICAL" if any(c.severity == Severity.CRITICAL and c.result == CheckResult.FAIL for c in self.checks) else "NEEDS ATTENTION"
        elif warnings > passed:
            grade = "NEEDS REVIEW"
        else:
            grade = "ACCEPTABLE"
        
        report = AuditReport(
            timestamp=start.isoformat(),
            target=self.target_network,
            duration_seconds=duration,
            total_checks=total,
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            errors=errors,
            score=score,
            checks=self.checks,
            summary=f"Security Posture: {grade} | Score: {score:.1f}% | Critical Issues: {failed}"
        )
        
        logger.info("\n" + "="*60)
        logger.info("AUDIT COMPLETE")
        logger.info("="*60)
        logger.info(f"Duration: {duration:.1f}s")
        logger.info(f"Total Checks: {total}")
        logger.info(f"  PASS: {passed} | FAIL: {failed} | WARNING: {warnings}")
        logger.info(f"Score: {score:.1f}%")
        logger.info(f"Status: {grade}")
        
        return report
    
    def export_report(self, report: AuditReport, filename: str = "security_audit_report.json"):
        data = {
            "report_info": {
                "timestamp": report.timestamp,
                "target": report.target,
                "duration_seconds": report.duration_seconds,
                "tool": "5G-Gibbon Security Auditor"
            },
            "summary": {
                "total_checks": report.total_checks,
                "passed": report.passed,
                "failed": report.failed,
                "warnings": report.warnings,
                "score": report.score,
                "status": report.summary
            },
            "checks": []
        }
        
        for check in report.checks:
            data["checks"].append({
                "id": check.check_id,
                "name": check.name,
                "description": check.description,
                "category": check.category,
                "standard": check.standard.value,
                "severity": check.severity.name,
                "result": check.result.value,
                "details": check.details,
                "remediation": check.remediation,
                "evidence": check.evidence
            })
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Report exported to {filename}")
        return filename


def run_security_audit(upf_ip: Optional[str] = None, amf_ip: Optional[str] = None, 
                       smf_ip: Optional[str] = None, nrf_ip: Optional[str] = None,
                       output_file: str = "security_audit_report.json"):
    auditor = Security5GAuditor()
    report = auditor.run_full_audit(upf_ip, amf_ip, smf_ip, nrf_ip)
    auditor.export_report(report, output_file)
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="5G Security Audit")
    parser.add_argument("--upf", help="UPF IP address")
    parser.add_argument("--amf", help="AMF IP address")
    parser.add_argument("--smf", help="SMF IP address")
    parser.add_argument("--nrf", help="NRF IP address")
    parser.add_argument("--output", default="security_audit_report.json", help="Output file")
    args = parser.parse_args()
    
    run_security_audit(args.upf, args.amf, args.smf, args.nrf, args.output)

