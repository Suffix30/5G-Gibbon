#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import logging
import json
import socket
from datetime import datetime
from core.config import TEST_CONFIG, DETECTED_COMPONENTS
from enumeration.enhanced_enumeration import enhanced_teid_enumeration
from analysis.rate_limit_testing import detect_rate_limiting
from attacks.pfcp_attacks import pfcp_association_attack
from key_extraction.ngap_key_extraction import rogue_gnodeb_with_key_extraction

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OPEN5GS_COMPONENTS = {
    "UPF": [("127.0.0.7", 2152), ("127.0.0.7", 8805)],
    "AMF": [("127.0.0.5", 7777)],
    "SMF": [("127.0.0.4", 8805), ("127.0.0.4", 7777)],
    "NRF": [("127.0.0.10", 7777)],
    "AUSF": [("127.0.0.11", 7777)],
    "UDM": [("127.0.0.12", 7777)],
    "UDR": [("127.0.0.20", 7777)],
    "PCF": [("127.0.0.13", 7777)],
    "BSF": [("127.0.0.15", 7777)],
    "NSSF": [("127.0.0.14", 7777)],
}

def check_service(ip, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

class SecurityAudit:
    def __init__(self, client_name="Unknown Client"):
        self.client_name = client_name
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        self.discovered_components = {}
        self.missing_components = []
        self.security_controls = {}
        self.compliance_status = {}
    
    def discover_infrastructure(self):
        logger.info("=== Phase 1: Infrastructure Discovery ===")
        logger.info("Checking Open5GS components on localhost...")
        
        required_components = {
            "UPF": {"found": False, "ip": None, "services": []},
            "AMF": {"found": False, "ip": None, "services": []},
            "SMF": {"found": False, "ip": None, "services": []},
            "NRF": {"found": False, "ip": None, "services": []},
            "AUSF": {"found": False, "ip": None, "services": []},
            "UDM": {"found": False, "ip": None, "services": []},
            "UDR": {"found": False, "ip": None, "services": []},
            "PCF": {"found": False, "ip": None, "services": []},
            "BSF": {"found": False, "ip": None, "services": []},
            "NSSF": {"found": False, "ip": None, "services": []},
            "gNodeB": {"found": False, "ip": None, "services": []}
        }
        
        for comp_name, endpoints in OPEN5GS_COMPONENTS.items():
            for ip, port in endpoints:
                if check_service(ip, port):
                    required_components[comp_name]["found"] = True
                    required_components[comp_name]["ip"] = ip
                    required_components[comp_name]["services"].append(port)
        
        if DETECTED_COMPONENTS.get("upf_ip"):
            required_components["UPF"]["found"] = True
            required_components["UPF"]["ip"] = DETECTED_COMPONENTS["upf_ip"]
        if DETECTED_COMPONENTS.get("amf_ip"):
            required_components["AMF"]["found"] = True
            required_components["AMF"]["ip"] = DETECTED_COMPONENTS["amf_ip"]
        if DETECTED_COMPONENTS.get("smf_ip"):
            required_components["SMF"]["found"] = True
            required_components["SMF"]["ip"] = DETECTED_COMPONENTS["smf_ip"]
        
        self.discovered_components = required_components
        
        for comp_name, comp_data in required_components.items():
            if comp_data["found"]:
                logger.info(f"✓ {comp_name} found at {comp_data['ip']}")
                self.findings["info"].append(f"{comp_name} discovered at {comp_data['ip']}")
            else:
                logger.warning(f"✗ {comp_name} NOT FOUND")
                self.missing_components.append(comp_name)
                self.findings["high"].append(f"Missing critical component: {comp_name}")
        
        return required_components
    
    def test_network_isolation(self):
        logger.info("\n=== Phase 2: Network Isolation Testing ===")
        
        upf_ip = self.discovered_components.get("UPF", {}).get("ip")
        amf_ip = self.discovered_components.get("AMF", {}).get("ip")
        
        if not upf_ip:
            self.findings["critical"].append("Cannot test isolation - UPF not found")
            return False
        
        logger.info("Testing if user plane can reach control plane...")
        
        if amf_ip:
            keys = rogue_gnodeb_with_key_extraction(upf_ip, 12345, amf_ip, 67890, timeout=5)
            
            if keys and keys.get("found"):
                self.findings["critical"].append(
                    "CRITICAL: User plane can reach control plane and extract keys! "
                    "Network isolation FAILED."
                )
                self.security_controls["network_isolation"] = "FAILED"
                return False
            else:
                self.findings["info"].append("Control plane not reachable from user plane (GOOD)")
                self.security_controls["network_isolation"] = "PASS"
                return True
        else:
            self.findings["medium"].append("Cannot verify isolation - AMF not found")
            self.security_controls["network_isolation"] = "UNTESTED"
            return None
    
    def test_deep_packet_inspection(self):
        logger.info("\n=== Phase 3: Deep Packet Inspection Testing ===")
        
        upf_ip = self.discovered_components.get("UPF", {}).get("ip")
        
        if not upf_ip:
            self.findings["high"].append("Cannot test DPI - UPF not found")
            return False
        
        logger.info("Testing if UPF validates nested GTP-U packets...")
        
        from attacks.nested_tunnel_testing import test_nested_depth
        results = test_nested_depth(upf_ip, max_depth=3)
        
        nested_blocked = sum(1 for status in results.values() if status == "blocked")
        nested_accepted = sum(1 for status in results.values() if status == "sent")
        
        if nested_blocked > 0:
            self.findings["info"].append(f"DPI blocked {nested_blocked} nested tunnel attempts (GOOD)")
            self.security_controls["deep_packet_inspection"] = "PASS"
            return True
        elif nested_accepted > 0:
            self.findings["high"].append(
                f"HIGH: UPF accepts nested GTP-U tunnels ({nested_accepted} levels). "
                f"Deep Packet Inspection likely DISABLED."
            )
            self.security_controls["deep_packet_inspection"] = "FAILED"
            return False
        else:
            self.findings["info"].append("Nested tunnel test inconclusive")
            self.security_controls["deep_packet_inspection"] = "UNKNOWN"
            return False
    
    def test_rate_limiting(self):
        logger.info("\n=== Phase 4: Rate Limiting Testing ===")
        
        upf_ip = self.discovered_components.get("UPF", {}).get("ip")
        
        if not upf_ip:
            self.findings["medium"].append("Cannot test rate limiting - UPF not found")
            return False
        
        logger.info("Testing rate limiting defenses...")
        
        results = detect_rate_limiting(upf_ip, test_rates=[100, 500], test_duration=3)
        
        high_rate_accepted = False
        for rate, data in results.items():
            if rate >= 500 and data["response_rate"] > 80:
                high_rate_accepted = True
        
        if high_rate_accepted:
            self.findings["medium"].append(
                "MEDIUM: No rate limiting detected. Network vulnerable to enumeration attacks."
            )
            self.security_controls["rate_limiting"] = "FAILED"
            return False
        else:
            self.findings["info"].append("Rate limiting appears active (GOOD)")
            self.security_controls["rate_limiting"] = "PASS"
            return True
    
    def test_session_security(self):
        logger.info("\n=== Phase 5: Session Security Testing ===")
        
        upf_ip = self.discovered_components.get("UPF", {}).get("ip")
        
        if not upf_ip:
            self.findings["medium"].append("Cannot test sessions - UPF not found")
            return False
        
        logger.info("Testing TEID predictability and active sessions...")
        
        results = enhanced_teid_enumeration(upf_ip, 0, 100, parallel=True)
        
        active_count = len(results.get("active", []))
        live_count = len(results.get("live_sessions", []))
        
        if active_count > 0 or live_count > 0:
            self.findings["info"].append(f"Found {active_count + live_count} active sessions")
            
            teids = results.get("active", []) + results.get("live_sessions", [])
            if len(teids) > 1:
                if teids == list(range(min(teids), max(teids) + 1)):
                    self.findings["high"].append(
                        "HIGH: TEIDs are sequential/predictable. Session hijacking risk."
                    )
                    self.security_controls["teid_randomization"] = "FAILED"
                    return False
        
        self.findings["info"].append("No active sessions found or TEIDs randomized")
        self.security_controls["teid_randomization"] = "PASS"
        return True
    
    def test_pfcp_security(self):
        logger.info("\n=== Phase 6: PFCP Protocol Security ===")
        
        smf_ip = self.discovered_components.get("SMF", {}).get("ip")
        
        if not smf_ip:
            self.findings["medium"].append("Cannot test PFCP - SMF not found")
            return False
        
        logger.info("Testing PFCP association and session handling...")
        
        assoc_result = pfcp_association_attack(smf_ip)
        
        if assoc_result:
            self.findings["medium"].append(
                "MEDIUM: SMF accepts unauthenticated PFCP associations"
            )
            self.security_controls["pfcp_authentication"] = "FAILED"
            return False
        else:
            self.findings["info"].append("PFCP properly secured or SMF not responding")
            self.security_controls["pfcp_authentication"] = "PASS"
            return True
    
    def check_3gpp_compliance(self):
        logger.info("\n=== Phase 7: 3GPP Compliance Check ===")
        
        compliance_requirements = {
            "TS 33.501 - Network Isolation": self.security_controls.get("network_isolation") == "PASS",
            "TS 33.501 - DPI on GTP-U": self.security_controls.get("deep_packet_inspection") == "PASS",
            "TS 33.210 - Rate Limiting": self.security_controls.get("rate_limiting") == "PASS",
            "TS 33.501 - TEID Randomization": self.security_controls.get("teid_randomization") == "PASS",
            "TS 29.244 - PFCP Security": self.security_controls.get("pfcp_authentication") == "PASS"
        }
        
        self.compliance_status = compliance_requirements
        
        compliant_count = sum(1 for compliant in compliance_requirements.values() if compliant)
        total_count = len(compliance_requirements)
        
        compliance_percentage = (compliant_count / total_count * 100) if total_count > 0 else 0
        
        logger.info(f"\nCompliance Score: {compliant_count}/{total_count} ({compliance_percentage:.0f}%)")
        
        for requirement, status in compliance_requirements.items():
            status_str = "✓ PASS" if status else "✗ FAIL"
            logger.info(f"  {status_str} - {requirement}")
        
        return compliance_percentage
    
    def generate_report(self, output_file=None):
        logger.info("\n=== Generating Security Audit Report ===")
        
        if output_file is None:
            output_file = f"5G_Security_Audit_{self.client_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            "audit_metadata": {
                "client_name": self.client_name,
                "timestamp": self.timestamp,
                "auditor": "5G-Gibbon Security Toolkit",
                "version": "1.0"
            },
            "discovered_components": self.discovered_components,
            "missing_components": self.missing_components,
            "security_controls": self.security_controls,
            "compliance_status": self.compliance_status,
            "findings": self.findings,
            "recommendations": self.generate_recommendations()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"✓ Report saved to {output_file}")
        
        self.print_executive_summary()
        
        return output_file
    
    def generate_recommendations(self):
        recommendations = []
        
        for component in self.missing_components:
            recommendations.append({
                "priority": "HIGH",
                "component": component,
                "recommendation": f"Deploy missing {component} component to complete 5G core",
                "reference": "3GPP TS 23.501"
            })
        
        if self.security_controls.get("network_isolation") == "FAILED":
            recommendations.append({
                "priority": "CRITICAL",
                "component": "Network Architecture",
                "recommendation": "Implement strict network isolation between user plane and control plane. Use separate VLANs/subnets with firewall rules.",
                "reference": "3GPP TS 33.501 Section 6.2"
            })
        
        if self.security_controls.get("deep_packet_inspection") == "FAILED":
            recommendations.append({
                "priority": "HIGH",
                "component": "UPF",
                "recommendation": "Enable Deep Packet Inspection on UPF. Configure to drop nested GTP-U packets.",
                "reference": "GSMA FS.37"
            })
        
        if self.security_controls.get("rate_limiting") == "FAILED":
            recommendations.append({
                "priority": "MEDIUM",
                "component": "UPF",
                "recommendation": "Implement rate limiting on TEID probes (max 10 pps per session).",
                "reference": "3GPP TS 33.210"
            })
        
        if self.security_controls.get("teid_randomization") == "FAILED":
            recommendations.append({
                "priority": "HIGH",
                "component": "SMF/UPF",
                "recommendation": "Use full 32-bit entropy for TEID allocation. Avoid sequential assignment.",
                "reference": "3GPP TS 29.281"
            })
        
        return recommendations
    
    def print_executive_summary(self):
        print("\n" + "=" * 80)
        print(f"5G SECURITY AUDIT - EXECUTIVE SUMMARY")
        print(f"Client: {self.client_name}")
        print(f"Date: {self.timestamp}")
        print("=" * 80)
        
        print(f"\n📊 INFRASTRUCTURE STATUS:")
        print(f"  Components Found: {sum(1 for c in self.discovered_components.values() if c['found'])}/8")
        print(f"  Missing Components: {len(self.missing_components)}")
        
        print(f"\n🔒 SECURITY CONTROLS:")
        for control, status in self.security_controls.items():
            icon = "✓" if status == "PASS" else "✗" if status == "FAILED" else "⚠"
            print(f"  {icon} {control.replace('_', ' ').title()}: {status}")
        
        print(f"\n⚠️  FINDINGS SUMMARY:")
        print(f"  Critical: {len(self.findings['critical'])}")
        print(f"  High: {len(self.findings['high'])}")
        print(f"  Medium: {len(self.findings['medium'])}")
        print(f"  Low: {len(self.findings['low'])}")
        print(f"  Info: {len(self.findings['info'])}")
        
        if self.findings['critical']:
            print(f"\n🚨 CRITICAL FINDINGS:")
            for finding in self.findings['critical']:
                print(f"  • {finding}")
        
        if self.findings['high']:
            print(f"\n⚠️  HIGH PRIORITY FINDINGS:")
            for finding in self.findings['high'][:3]:
                print(f"  • {finding}")
        
        print("\n" + "=" * 80)

def run_full_audit(client_name="Test Client"):
    audit = SecurityAudit(client_name)
    
    audit.discover_infrastructure()
    audit.test_network_isolation()
    audit.test_deep_packet_inspection()
    audit.test_rate_limiting()
    audit.test_session_security()
    audit.test_pfcp_security()
    
    _ = audit.check_3gpp_compliance()
    
    report_file = audit.generate_report()
    
    return audit, report_file

def run_test_config_audit() -> SecurityAudit:
    upf_ip = TEST_CONFIG.get("upf_ip", "127.0.0.7")
    amf_ip = TEST_CONFIG.get("amf_ip", "127.0.0.5")
    smf_ip = TEST_CONFIG.get("smf_ip", "127.0.0.4")
    
    logger.info(f"Running audit with TEST_CONFIG: UPF={upf_ip}, AMF={amf_ip}, SMF={smf_ip}")
    
    audit = SecurityAudit("TEST_CONFIG Lab")
    
    component_map = {"UPF": upf_ip, "AMF": amf_ip, "SMF": smf_ip}
    for component, ip in component_map.items():
        reachable = socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex((ip, 7777)) == 0
        audit.discovered_components[component] = {"found": reachable, "ip": ip, "services": []}
    
    return audit


if __name__ == "__main__":
    audit, report = run_full_audit("Test Lab")
    logger.info(f"\n Audit complete. Report: {report}")

