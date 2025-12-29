#!/usr/bin/env python3
"""
5G-Gibbon Toolkit Test Suite
============================
Tests all modules for import errors, function validity, and basic operation.
Does NOT send any network packets - safe to run anywhere.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
from typing import Dict, Tuple, Any

class ToolkitTester:
    def __init__(self):
        self.results: Dict[str, Dict[str, Any]] = {}
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        
    def test_import(self, module_path: str) -> Tuple[bool, str]:
        try:
            module = importlib.import_module(module_path)
            return True, f"OK - {len(dir(module))} attributes"
        except Exception as e:
            return False, f"FAIL - {type(e).__name__}: {str(e)[:100]}"
    
    def test_function(self, func, *args, **kwargs) -> Tuple[bool, str]:
        try:
            result = func(*args, **kwargs)
            return True, f"OK - returned {type(result).__name__}"
        except Exception as e:
            return False, f"FAIL - {type(e).__name__}: {str(e)[:100]}"
    
    def print_header(self, text: str):
        print(f"\n{'='*60}")
        print(f" {text}")
        print(f"{'='*60}")
    
    def print_result(self, name: str, passed: bool, msg: str):
        status = "[OK]" if passed else "[FAIL]"
        print(f"  {status} {name}: {msg}")
        
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def run_all_tests(self):
        print("\n" + "="*60)
        print(" 5G-GIBBON TOOLKIT TEST SUITE")
        print("="*60)
        print(" Testing all modules without sending network packets")
        print("="*60)
        
        self.test_core_modules()
        self.test_protocol_modules()
        self.test_discovery_modules()
        self.test_enumeration_modules()
        self.test_attack_modules()
        self.test_key_extraction_modules()
        self.test_defense_modules()
        self.test_analysis_modules()
        self.test_utility_modules()
        self.test_cli_module()
        self.test_packet_crafting()
        self.test_data_structures()
        
        self.print_summary()
    
    def test_core_modules(self):
        self.print_header("CORE MODULES")
        
        modules = [
            "core.config",
            "core.cli",
            "core.response_verifier",
            "core.logger_config",
            "core.results_db",
            "core.resource_manager",
            "core.progress_tracker",
            "core.async_utils",
            "core.streaming",
            "core.adaptive_rate",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_protocol_modules(self):
        self.print_header("PROTOCOL MODULES")
        
        modules = [
            "protocol.protocol_layers",
            "protocol.http2_sbi",
            "protocol.sctp_enhanced",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_discovery_modules(self):
        self.print_header("DISCOVERY MODULES")
        
        modules = [
            "discovery.network_discovery",
            "discovery.network_scanner",
            "discovery.quick_discovery",
            "discovery.async_scanner",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_enumeration_modules(self):
        self.print_header("ENUMERATION MODULES")
        
        modules = [
            "enumeration.teid_seid_enumeration",
            "enumeration.async_enumeration",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_attack_modules(self):
        self.print_header("ATTACK MODULES")
        
        modules = [
            "attacks.billing_fraud",
            "attacks.nested_tunnel_testing",
            "attacks.ngap_injection",
            "attacks.pfcp_attacks",
            "attacks.rogue_gnodeb",
            "attacks.ue_to_ue_injection",
            "attacks.advanced_gnb_registration",
            "attacks.async_attacks",
            "attacks.protocol_fuzzer",
            "attacks.timing_attacks",
            "attacks.side_channel",
            "attacks.advanced_fuzzing",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_key_extraction_modules(self):
        self.print_header("KEY EXTRACTION MODULES")
        
        modules = [
            "key_extraction.ngap_key_extraction",
            "key_extraction.nuclear_key_extraction",
            "key_extraction.maximum_extraction",
            "key_extraction.key_extraction_stress",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_defense_modules(self):
        self.print_header("DEFENSE MODULES")
        
        modules = [
            "defense.ultra_blue_team",
            "defense.ids_signatures",
            "defense.honeypot",
            "defense.anomaly_detector",
            "defense.security_audit",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_analysis_modules(self):
        self.print_header("ANALYSIS MODULES")
        
        modules = [
            "analysis.packet_capture",
            "analysis.rate_limit_testing",
            "analysis.traffic_analyzer",
            "analysis.session_tracker",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_utility_modules(self):
        self.print_header("UTILITY MODULES")
        
        modules = [
            "utils.performance_monitor",
            "reporting.html_report",
            "reporting.visualization",
            "reporting.dashboard",
        ]
        
        for mod in modules:
            passed, msg = self.test_import(mod)
            self.print_result(mod, passed, msg)
    
    def test_cli_module(self):
        self.print_header("CLI TESTS")
        
        try:
            from core.cli import setup_argparse
            parser = setup_argparse()
            
            test_args = [
                [],
                ["--help"],
                ["discover"],
                ["attack", "billing"],
                ["keys"],
            ]
            
            for args in test_args:
                try:
                    if "--help" in args:
                        continue
                    parser.parse_args(args)
                    self.print_result(f"CLI parse {args}", True, "OK")
                except SystemExit:
                    self.print_result(f"CLI parse {args}", True, "OK (expected exit)")
                except Exception as e:
                    self.print_result(f"CLI parse {args}", False, str(e)[:50])
        except Exception as e:
            self.print_result("CLI setup", False, str(e)[:100])
    
    def test_packet_crafting(self):
        self.print_header("PACKET CRAFTING (no send)")
        
        try:
            from protocol.protocol_layers import PFCPHeader, NGAPHeader, craft_ngap_setup_request, craft_pfcp_session_establishment
            
            pfcp = PFCPHeader()
            self.print_result("PFCPHeader creation", True, f"OK - {len(bytes(pfcp))} bytes")
            
            ngap = NGAPHeader()
            self.print_result("NGAPHeader creation", True, f"OK - {len(bytes(ngap))} bytes")
            
            ngap_setup = craft_ngap_setup_request()
            self.print_result("NGAP Setup Request", True, f"OK - {len(ngap_setup)} bytes")
            
            pfcp_sess = craft_pfcp_session_establishment()
            self.print_result("PFCP Session Establishment", True, f"OK - {len(pfcp_sess)} bytes")
            
        except Exception as e:
            self.print_result("Packet crafting", False, str(e)[:100])
        
        try:
            from attacks.advanced_gnb_registration import craft_proper_ng_setup_request, craft_sctp_init, craft_sctp_data
            
            ng_setup = craft_proper_ng_setup_request(gnb_id=0x123456)
            self.print_result("Proper NG Setup", True, f"OK - {len(ng_setup)} bytes")
            
            sctp_init = craft_sctp_init()
            self.print_result("SCTP INIT chunk", True, f"OK - {len(sctp_init)} bytes")
            
            sctp_data = craft_sctp_data(0, 0, 60, b"test")
            self.print_result("SCTP DATA chunk", True, f"OK - {len(sctp_data)} bytes")
            
        except Exception as e:
            self.print_result("Advanced packet crafting", False, str(e)[:100])
    
    def test_data_structures(self):
        self.print_header("DATA STRUCTURES")
        
        try:
            from core.config import TEST_CONFIG, DETECTED_COMPONENTS
            
            required_keys = ["upf_ip", "amf_ip", "smf_ip", "interface", "teid_range", "seid_range"]
            missing = [k for k in required_keys if k not in TEST_CONFIG]
            
            if missing:
                self.print_result("TEST_CONFIG keys", False, f"Missing: {missing}")
            else:
                self.print_result("TEST_CONFIG keys", True, f"OK - {len(TEST_CONFIG)} keys")
            
            self.print_result("DETECTED_COMPONENTS", True, f"OK - {len(DETECTED_COMPONENTS)} entries")
            
        except Exception as e:
            self.print_result("Config structures", False, str(e)[:100])
        
        try:
            from core.response_verifier import ResponseVerifier
            
            verifier = ResponseVerifier(timeout=1.0)
            
            result = verifier.verify_gtp_response(None)
            if result.get("success") == False and result.get("reason") == "no_response":
                self.print_result("ResponseVerifier.verify_gtp_response(None)", True, "OK - handles null")
            else:
                self.print_result("ResponseVerifier.verify_gtp_response(None)", False, f"Unexpected: {result}")
            
            result = verifier.verify_pfcp_response(None)
            if result.get("success") == False:
                self.print_result("ResponseVerifier.verify_pfcp_response(None)", True, "OK - handles null")
            else:
                self.print_result("ResponseVerifier.verify_pfcp_response(None)", False, f"Unexpected: {result}")
                
        except Exception as e:
            self.print_result("ResponseVerifier", False, str(e)[:100])
        
        try:
            from core.results_db import ResultsDatabase
            
            import tempfile
            db_path = os.path.join(tempfile.gettempdir(), "test_5g.db")
            db = ResultsDatabase(db_path)
            
            db.save_attack_result(
                attack_type="test",
                target_ip="127.0.0.1",
                success=True,
                raw_data={"test": True}
            )
            
            results = db.get_recent_attacks(limit=10)
            if len(results) >= 1:
                self.print_result("ResultsDatabase save/get", True, f"OK - {len(results)} results")
            else:
                self.print_result("ResultsDatabase save/get", False, "No results returned")
                
        except Exception as e:
            self.print_result("ResultsDatabase", False, str(e)[:100])
    
    def print_summary(self):
        print("\n" + "="*60)
        print(" TEST SUMMARY")
        print("="*60)
        
        total = self.passed + self.failed
        pass_rate = (self.passed / total * 100) if total > 0 else 0
        
        print(f"\n  Total Tests:  {total}")
        print(f"  Passed:       {self.passed}")
        print(f"  Failed:       {self.failed}")
        print(f"  Pass Rate:    {pass_rate:.1f}%")
        
        _scapy_failures = sum(1 for r in self.results.values() 
                             if isinstance(r, dict) and "scapy" in str(r.get("error", "")).lower())
        
        if self.failed == 0:
            print(f"\n  ALL TESTS PASSED!")
        else:
            print(f"\n  {self.failed} TESTS FAILED")
            
            try:
                import scapy as _scapy_check
                _ = _scapy_check
            except ImportError:
                print(f"\n  NOTE: Most failures are due to missing 'scapy' library.")
                print(f"  Install dependencies with:")
                print(f"    pip install -r requirements.txt")
                print(f"  Or just scapy:")
                print(f"    pip install scapy")
        
        print("\n" + "="*60 + "\n")
        
        return self.failed == 0


def main():
    tester = ToolkitTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

