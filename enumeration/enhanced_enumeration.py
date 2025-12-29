#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from scapy.config import conf
from scapy.contrib.gtp import GTPHeader
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import TEST_CONFIG, validate_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_gtp_response(resp):
    if not resp:
        return "silent_drop"
    
    if resp.haslayer(GTPHeader):
        gtp_type = resp[GTPHeader].gtp_type
        
        if gtp_type == 1:
            return "echo_request"
        elif gtp_type == 2:
            return "echo_response"
        elif gtp_type == 26:
            return "error_indication"
        elif gtp_type == 31:
            return "end_marker"
        elif gtp_type == 254:
            return "g_pdu"
        elif gtp_type == 255:
            return "t_pdu"
        else:
            return f"unknown_type_{gtp_type}"
    
    if resp.haslayer(IP):
        if resp[IP].proto == 1:
            return "icmp_response"
        elif resp[IP].proto == 17:
            return "udp_response"
    
    return "other_response"

def probe_teid_with_analysis(upf_ip, teid, timeout, iface):
    try:
        pkt = IP(dst=upf_ip)/UDP(dport=2152)/GTPHeader(teid=teid, gtp_type=1)
        resp = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
        
        response_type = analyze_gtp_response(resp)
        
        if response_type == "echo_response":
            return (teid, "active", response_type)
        elif response_type == "error_indication":
            return (teid, "live_session", response_type)
        elif response_type != "silent_drop":
            return (teid, "responding", response_type)
        else:
            return (teid, "inactive", response_type)
    except Exception as e:
        logger.debug(f"Error probing TEID {teid}: {e}")
        return (teid, "error", "exception")

def enhanced_teid_enumeration(upf_ip, start_teid=0, end_teid=100, iface=None, parallel=True, workers=10):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    validate_config()
    conf.L3socket = conf.L3socket
    
    results = {
        "active": [],
        "live_sessions": [],
        "error_indications": [],
        "other_responses": [],
        "silent_drops": []
    }
    
    response_stats = {}
    
    logger.info(f"Enhanced TEID enumeration: {start_teid}-{end_teid} on {upf_ip}")
    
    timeout = TEST_CONFIG["enum_timeout"]
    
    try:
        if parallel:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(probe_teid_with_analysis, upf_ip, teid, timeout, iface): teid 
                          for teid in range(start_teid, end_teid)}
                
                for future in as_completed(futures):
                    teid, status, response_type = future.result()
                    
                    response_stats[response_type] = response_stats.get(response_type, 0) + 1
                    
                    if status == "active":
                        results["active"].append(teid)
                        logger.info(f"✓ Active TEID {teid} (echo_response)")
                    elif status == "live_session":
                        results["live_sessions"].append(teid)
                        logger.info(f"✓ Live session TEID {teid} (error_indication)")
                    elif response_type == "error_indication":
                        results["error_indications"].append(teid)
                        logger.info(f"⚠ Error indication for TEID {teid}")
                    elif status == "responding":
                        results["other_responses"].append(teid)
                        logger.debug(f"? Response for TEID {teid}: {response_type}")
                    else:
                        results["silent_drops"].append(teid)
        else:
            for teid in range(start_teid, end_teid):
                teid, status, response_type = probe_teid_with_analysis(upf_ip, teid, timeout, iface)
                
                response_stats[response_type] = response_stats.get(response_type, 0) + 1
                
                if status == "active":
                    results["active"].append(teid)
                    logger.info(f"✓ Active TEID {teid}")
                elif status == "live_session":
                    results["live_sessions"].append(teid)
                    logger.info(f"✓ Live session TEID {teid}")
                elif response_type == "error_indication":
                    results["error_indications"].append(teid)
                
                if teid % 20 == 0:
                    logger.debug(f"Progress: {teid}/{end_teid}")
        
        logger.info("\n=== Enumeration Results ===")
        logger.info(f"Active TEIDs: {len(results['active'])}")
        logger.info(f"Live sessions: {len(results['live_sessions'])}")
        logger.info(f"Error indications: {len(results['error_indications'])}")
        logger.info(f"Other responses: {len(results['other_responses'])}")
        logger.info(f"Silent drops: {len(results['silent_drops'])}")
        
        logger.info("\n=== Response Type Statistics ===")
        for resp_type, count in sorted(response_stats.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"{resp_type}: {count}")
        
        return results
    except Exception as e:
        logger.error(f"Enhanced enumeration failed: {e}")
        return results

def topology_mapping(upf_ip, teid_results, iface=None):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    
    logger.info("\n=== Topology Mapping ===")
    
    interesting_teids = (
        teid_results.get("active", []) + 
        teid_results.get("live_sessions", []) + 
        teid_results.get("error_indications", [])
    )
    
    if not interesting_teids:
        logger.warning("No interesting TEIDs found for topology mapping")
        return {}
    
    topology = {}
    
    for teid in interesting_teids[:10]:
        logger.info(f"Mapping TEID {teid}...")
        
        try:
            pkt = IP(dst=upf_ip)/UDP(dport=2152)/GTPHeader(teid=teid, gtp_type=1)
            resp = sr1(pkt, timeout=1, iface=iface, verbose=0)
            
            if resp and resp.haslayer(IP):
                topology[teid] = {
                    "src_ip": resp[IP].src,
                    "dst_ip": resp[IP].dst,
                    "ttl": resp[IP].ttl,
                    "response_type": analyze_gtp_response(resp)
                }
                logger.info(f"  TEID {teid} -> {resp[IP].src}")
        except Exception as e:
            logger.debug(f"Mapping failed for TEID {teid}: {e}")
    
    return topology

if __name__ == "__main__":
    upf_ip = TEST_CONFIG["upf_ip"]
    
    results = enhanced_teid_enumeration(upf_ip, 0, 50, parallel=True, workers=10)
    
    topology = topology_mapping(upf_ip, results)
    
    logger.info(f"\nTopology mapped: {len(topology)} nodes")

