#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RuleFormat(Enum):
    SNORT = "snort"
    SURICATA = "suricata"
    IPTABLES = "iptables"
    NFTABLES = "nftables"


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class IDSRule:
    name: str
    description: str
    severity: Severity
    protocol: str
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    content: Optional[bytes] = None
    content_hex: Optional[str] = None
    pcre: Optional[str] = None
    flow: str = "to_server,established"
    sid: int = 0
    rev: int = 1
    classtype: str = "attempted-admin"
    metadata: Dict = field(default_factory=dict)


class IDSSignatureGenerator:
    def __init__(self, output_format: RuleFormat = RuleFormat.SURICATA):
        self.format = output_format
        self.rules: List[IDSRule] = []
        self.sid_base = 5000000
        self.generated_count = 0
        
    def generate_5g_attack_signatures(self) -> List[IDSRule]:
        logger.info("Generating 5G attack detection signatures...")
        
        self._add_gtp_signatures()
        self._add_pfcp_signatures()
        self._add_ngap_signatures()
        self._add_sbi_signatures()
        self._add_dos_signatures()
        self._add_injection_signatures()
        
        logger.info(f"Generated {len(self.rules)} IDS signatures")
        return self.rules
    
    def _add_gtp_signatures(self):
        self.rules.extend([
            IDSRule(
                name="5G-GIBBON GTP-U Tunnel Probe",
                description="Detects GTP-U echo request probing for active tunnels",
                severity=Severity.MEDIUM,
                protocol="udp",
                dst_port="2152",
                content_hex="|30 01|",
                classtype="attempted-recon",
                metadata={"attack": "teid_enumeration", "mitre": "T1046"}
            ),
            IDSRule(
                name="5G-GIBBON Nested GTP-U Attack",
                description="Detects nested GTP-U tunneling attack (tunnel-in-tunnel)",
                severity=Severity.CRITICAL,
                protocol="udp",
                dst_port="2152",
                content_hex="|30 ff|",
                pcre="/\\x30.{3,7}\\x30\\xff/",
                classtype="attempted-admin",
                metadata={"attack": "nested_tunnel", "mitre": "T1572"}
            ),
            IDSRule(
                name="5G-GIBBON GTP-U Malformed Header",
                description="Detects malformed GTP-U headers indicating fuzzing",
                severity=Severity.HIGH,
                protocol="udp",
                dst_port="2152",
                content_hex="|30 ff ff ff|",
                classtype="protocol-command-decode",
                metadata={"attack": "gtp_fuzzing", "mitre": "T1499"}
            ),
            IDSRule(
                name="5G-GIBBON High-Rate TEID Scan",
                description="Detects rapid TEID enumeration attempts",
                severity=Severity.HIGH,
                protocol="udp",
                dst_port="2152",
                content_hex="|30 01 00|",
                metadata={"attack": "teid_bruteforce", "mitre": "T1046", "threshold": "100/10s"}
            ),
            IDSRule(
                name="5G-GIBBON GTP-U Session Hijack",
                description="Detects potential GTP-U session hijacking attempt",
                severity=Severity.CRITICAL,
                protocol="udp",
                dst_port="2152",
                content_hex="|30 ff 00|",
                classtype="attempted-admin",
                metadata={"attack": "session_hijack", "mitre": "T1557"}
            ),
        ])
    
    def _add_pfcp_signatures(self):
        self.rules.extend([
            IDSRule(
                name="5G-GIBBON PFCP Association Flood",
                description="Detects PFCP association request flooding",
                severity=Severity.HIGH,
                protocol="udp",
                dst_port="8805",
                content_hex="|20 01|",
                classtype="attempted-dos",
                metadata={"attack": "pfcp_flood", "mitre": "T1499", "threshold": "50/10s"}
            ),
            IDSRule(
                name="5G-GIBBON PFCP Session Manipulation",
                description="Detects unauthorized PFCP session modification",
                severity=Severity.CRITICAL,
                protocol="udp",
                dst_port="8805",
                content_hex="|20 34|",
                classtype="attempted-admin",
                metadata={"attack": "pfcp_session_mod", "mitre": "T1565"}
            ),
            IDSRule(
                name="5G-GIBBON PFCP Malformed Message",
                description="Detects malformed PFCP messages indicating attack",
                severity=Severity.HIGH,
                protocol="udp",
                dst_port="8805",
                pcre="/\\x20[\\x00-\\xff]{2}\\xff{4}/",
                classtype="protocol-command-decode",
                metadata={"attack": "pfcp_fuzzing", "mitre": "T1499"}
            ),
            IDSRule(
                name="5G-GIBBON PFCP SEID Enumeration",
                description="Detects SEID brute-force enumeration",
                severity=Severity.MEDIUM,
                protocol="udp",
                dst_port="8805",
                content_hex="|21 32|",
                metadata={"attack": "seid_enum", "mitre": "T1046", "threshold": "100/10s"}
            ),
        ])
    
    def _add_ngap_signatures(self):
        self.rules.extend([
            IDSRule(
                name="5G-GIBBON Rogue gNodeB Registration",
                description="Detects unauthorized gNodeB NG Setup Request",
                severity=Severity.CRITICAL,
                protocol="sctp",
                dst_port="38412",
                content_hex="|00 15|",
                classtype="attempted-admin",
                metadata={"attack": "rogue_gnb", "mitre": "T1200"}
            ),
            IDSRule(
                name="5G-GIBBON NGAP Injection via GTP",
                description="Detects NGAP messages tunneled through GTP-U",
                severity=Severity.CRITICAL,
                protocol="udp",
                dst_port="2152",
                pcre="/\\x30.{7,}\\x00\\x15/",
                classtype="attempted-admin",
                metadata={"attack": "ngap_injection", "mitre": "T1055"}
            ),
            IDSRule(
                name="5G-GIBBON Fake UE Registration Flood",
                description="Detects mass fake UE registration attempts",
                severity=Severity.HIGH,
                protocol="sctp",
                dst_port="38412",
                content_hex="|00 0f 40|",
                metadata={"attack": "fake_ue_flood", "mitre": "T1499", "threshold": "20/10s"}
            ),
            IDSRule(
                name="5G-GIBBON Handover Attack",
                description="Detects suspicious handover request patterns",
                severity=Severity.HIGH,
                protocol="sctp",
                dst_port="38412",
                content_hex="|00 00 40|",
                classtype="attempted-admin",
                metadata={"attack": "handover_attack", "mitre": "T1557"}
            ),
        ])
    
    def _add_sbi_signatures(self):
        self.rules.extend([
            IDSRule(
                name="5G-GIBBON SBI NF Discovery Probe",
                description="Detects NRF discovery enumeration",
                severity=Severity.MEDIUM,
                protocol="tcp",
                dst_port="7777",
                pcre="/GET.*\\/nnrf-disc\\/v1\\/nf-instances/",
                classtype="attempted-recon",
                metadata={"attack": "nf_discovery", "mitre": "T1046"}
            ),
            IDSRule(
                name="5G-GIBBON Rogue NF Registration",
                description="Detects unauthorized NF registration attempt",
                severity=Severity.CRITICAL,
                protocol="tcp",
                dst_port="7777",
                pcre="/PUT.*\\/nnrf-nfm\\/v1\\/nf-instances/",
                classtype="attempted-admin",
                metadata={"attack": "rogue_nf", "mitre": "T1200"}
            ),
            IDSRule(
                name="5G-GIBBON Subscriber Data Extraction",
                description="Detects UDM subscriber data query attacks",
                severity=Severity.CRITICAL,
                protocol="tcp",
                dst_port="7777",
                pcre="/GET.*\\/nudm-sdm\\/.*\\/am-data/",
                classtype="attempted-admin",
                metadata={"attack": "subscriber_extraction", "mitre": "T1530"}
            ),
            IDSRule(
                name="5G-GIBBON Auth Data Theft",
                description="Detects authentication data extraction attempts",
                severity=Severity.CRITICAL,
                protocol="tcp",
                dst_port="7777",
                pcre="/GET.*security-information|authentication-subscription/",
                classtype="attempted-admin",
                metadata={"attack": "auth_theft", "mitre": "T1552"}
            ),
        ])
    
    def _add_dos_signatures(self):
        self.rules.extend([
            IDSRule(
                name="5G-GIBBON GTP-U Flood Attack",
                description="Detects high-rate GTP-U flooding",
                severity=Severity.HIGH,
                protocol="udp",
                dst_port="2152",
                classtype="attempted-dos",
                metadata={"attack": "gtp_flood", "mitre": "T1498", "threshold": "1000/1s"}
            ),
            IDSRule(
                name="5G-GIBBON SCTP Flood Attack",
                description="Detects SCTP-based DoS on NGAP interface",
                severity=Severity.HIGH,
                protocol="sctp",
                dst_port="38412",
                classtype="attempted-dos",
                metadata={"attack": "sctp_flood", "mitre": "T1498", "threshold": "500/1s"}
            ),
        ])
    
    def _add_injection_signatures(self):
        self.rules.extend([
            IDSRule(
                name="5G-GIBBON Billing Fraud Attempt",
                description="Detects billing manipulation via GTP",
                severity=Severity.CRITICAL,
                protocol="udp",
                dst_port="2152",
                pcre="/\\x30\\xff.{4,}\\x45\\x00/",
                classtype="attempted-admin",
                metadata={"attack": "billing_fraud", "mitre": "T1565"}
            ),
            IDSRule(
                name="5G-GIBBON UE-to-UE Injection",
                description="Detects cross-UE traffic injection attack",
                severity=Severity.CRITICAL,
                protocol="udp",
                dst_port="2152",
                pcre="/\\x30.{7,}\\x45\\x00.{8,}\\x01/",
                classtype="attempted-admin",
                metadata={"attack": "ue_injection", "mitre": "T1557"}
            ),
        ])
    
    def export_snort(self, filename: str = "5g_gibbon_snort.rules"):
        rules_text = self._generate_snort_rules()
        
        with open(filename, 'w') as f:
            f.write(f"# 5G-Gibbon IDS Signatures for Snort\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total Rules: {len(self.rules)}\n\n")
            f.write(rules_text)
        
        logger.info(f"Exported {len(self.rules)} Snort rules to {filename}")
        return filename
    
    def export_suricata(self, filename: str = "5g_gibbon_suricata.rules"):
        rules_text = self._generate_suricata_rules()
        
        with open(filename, 'w') as f:
            f.write(f"# 5G-Gibbon IDS Signatures for Suricata\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total Rules: {len(self.rules)}\n\n")
            f.write(rules_text)
        
        logger.info(f"Exported {len(self.rules)} Suricata rules to {filename}")
        return filename
    
    def export_iptables(self, filename: str = "5g_gibbon_iptables.sh"):
        rules_text = self._generate_iptables_rules()
        
        with open(filename, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# 5G-Gibbon Firewall Rules for iptables\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            f.write(rules_text)
        
        logger.info(f"Exported iptables rules to {filename}")
        return filename
    
    def _generate_snort_rules(self) -> str:
        lines = []
        for i, rule in enumerate(self.rules):
            sid = self.sid_base + i
            
            content_part = ""
            if rule.content_hex:
                content_part = f'content:"{rule.content_hex}"; '
            if rule.pcre:
                content_part += f'pcre:"{rule.pcre}"; '
            
            priority = 5 - rule.severity.value
            
            line = (
                f'alert {rule.protocol} {rule.src_ip} {rule.src_port} -> '
                f'{rule.dst_ip} {rule.dst_port} '
                f'(msg:"{rule.name}"; {content_part}'
                f'flow:{rule.flow}; classtype:{rule.classtype}; '
                f'sid:{sid}; rev:{rule.rev}; priority:{priority};)'
            )
            lines.append(line)
        
        return "\n".join(lines)
    
    def _generate_suricata_rules(self) -> str:
        lines = []
        for i, rule in enumerate(self.rules):
            sid = self.sid_base + i
            
            content_part = ""
            if rule.content_hex:
                hex_clean = rule.content_hex.replace("|", "")
                content_part = f'content:"|{hex_clean}|"; '
            if rule.pcre:
                content_part += f'pcre:"{rule.pcre}"; '
            
            metadata_str = "; ".join(f"{k} {v}" for k, v in rule.metadata.items())
            
            line = (
                f'alert {rule.protocol} {rule.src_ip} {rule.src_port} -> '
                f'{rule.dst_ip} {rule.dst_port} '
                f'(msg:"{rule.name}"; {content_part}'
                f'classtype:{rule.classtype}; '
                f'sid:{sid}; rev:{rule.rev}; '
                f'metadata:{metadata_str};)'
            )
            lines.append(line)
        
        return "\n".join(lines)
    
    def _generate_iptables_rules(self) -> str:
        lines = [
            "# Create 5G protection chain",
            "iptables -N GIBBON_5G_PROTECT 2>/dev/null || iptables -F GIBBON_5G_PROTECT",
            "",
            "# GTP-U Protection (port 2152)",
            "iptables -A GIBBON_5G_PROTECT -p udp --dport 2152 -m string --algo bm --hex-string '|30ff|' -j DROP",
            "iptables -A GIBBON_5G_PROTECT -p udp --dport 2152 -m hashlimit --hashlimit-above 1000/sec --hashlimit-mode srcip --hashlimit-name gtp_limit -j DROP",
            "",
            "# PFCP Protection (port 8805)", 
            "iptables -A GIBBON_5G_PROTECT -p udp --dport 8805 -m hashlimit --hashlimit-above 100/sec --hashlimit-mode srcip --hashlimit-name pfcp_limit -j DROP",
            "",
            "# NGAP Protection (port 38412)",
            "iptables -A GIBBON_5G_PROTECT -p sctp --dport 38412 -m hashlimit --hashlimit-above 50/sec --hashlimit-mode srcip --hashlimit-name ngap_limit -j DROP",
            "",
            "# SBI Protection (port 7777)",
            "iptables -A GIBBON_5G_PROTECT -p tcp --dport 7777 -m hashlimit --hashlimit-above 100/sec --hashlimit-mode srcip --hashlimit-name sbi_limit -j DROP",
            "",
            "# Apply to INPUT chain",
            "iptables -D INPUT -j GIBBON_5G_PROTECT 2>/dev/null",
            "iptables -I INPUT -j GIBBON_5G_PROTECT",
            "",
            "echo '5G-Gibbon protection rules applied!'",
        ]
        return "\n".join(lines)
    
    def get_summary(self) -> Dict:
        by_severity = {}
        by_attack = {}
        
        for rule in self.rules:
            sev = rule.severity.name
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            attack = rule.metadata.get("attack", "unknown")
            by_attack[attack] = by_attack.get(attack, 0) + 1
        
        return {
            "total_rules": len(self.rules),
            "by_severity": by_severity,
            "by_attack_type": by_attack
        }


def generate_all_signatures(output_dir: str = "defense/signatures"):
    os.makedirs(output_dir, exist_ok=True)
    
    generator = IDSSignatureGenerator()
    generator.generate_5g_attack_signatures()
    
    generator.export_snort(os.path.join(output_dir, "5g_gibbon_snort.rules"))
    generator.export_suricata(os.path.join(output_dir, "5g_gibbon_suricata.rules"))
    generator.export_iptables(os.path.join(output_dir, "5g_gibbon_iptables.sh"))
    
    summary = generator.get_summary()
    
    logger.info("\n" + "="*50)
    logger.info("IDS SIGNATURE GENERATION COMPLETE")
    logger.info("="*50)
    logger.info(f"Total Rules: {summary['total_rules']}")
    logger.info(f"By Severity: {summary['by_severity']}")
    logger.info(f"Output: {output_dir}/")
    
    return summary


if __name__ == "__main__":
    generate_all_signatures()

