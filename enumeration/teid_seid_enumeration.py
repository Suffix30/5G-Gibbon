#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from scapy.config import conf
from scapy.contrib.gtp import GTPHeader
import socket
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import TEST_CONFIG, validate_config
from protocol.protocol_layers import PFCPHeader
from core.response_verifier import ResponseVerifier
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def probe_teid(upf_ip, teid, timeout, iface, verifier=None):
    try:
        pkt = IP(dst=upf_ip) / UDP(dport=2152) / GTPHeader(teid=teid, gtp_type=1)
        resp = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
        
        if resp:
            if verifier:
                verification = verifier.verify_gtp_response(resp, expected_teid=teid, expected_type=2)
                if verification.get("success"):
                    return (teid, "active", verification)
            
            if resp.haslayer(GTPHeader):
                gtp_type = resp[GTPHeader].gtp_type
                if gtp_type == 2:
                    return (teid, "active", {"gtp_type": 2})
                elif gtp_type == 26:
                    return (teid, "live_session", {"gtp_type": 26})
    except socket.timeout:
        return None
    except ConnectionError as e:
        logger.debug(f"Connection error probing TEID {teid}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Error probing TEID {teid}: {e}")
        return None
    return None

def enumerate_teid(upf_ip, start_teid=None, end_teid=None, iface=None, parallel=False, workers=10, show_progress=True):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    if start_teid is None:
        start_teid = TEST_CONFIG["teid_range"][0]
    if end_teid is None:
        end_teid = TEST_CONFIG["teid_range"][1]
    
    validate_config()
    conf.L3socket = conf.L3socket
    active_teids = []
    live_sessions = []
    timeout = TEST_CONFIG["enum_timeout"]
    delay = TEST_CONFIG["enum_delay"]
    verifier = ResponseVerifier(timeout=timeout)
    
    total_range = end_teid - start_teid
    logger.info(f"Enumerating TEIDs from {start_teid} to {end_teid} on {upf_ip} ({total_range} TEIDs)")
    
    console = Console() if show_progress else None
    
    try:
        if parallel:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Active: {task.fields[active]} | Live: {task.fields[live]}"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]TEID Enumeration",
                        total=total_range,
                        active=0,
                        live=0
                    )
                    
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        futures = {executor.submit(probe_teid, upf_ip, teid, timeout, iface, verifier): teid 
                                  for teid in range(start_teid, end_teid)}
                        
                        completed = 0
                        for future in as_completed(futures):
                            try:
                                result = future.result(timeout=timeout + 1)
                                if result:
                                    teid, status, _ = result
                                    if status == "active":
                                        active_teids.append(teid)
                                        logger.info(f"✓ Found active TEID: {teid}")
                                    elif status == "live_session":
                                        live_sessions.append(teid)
                                        logger.info(f"✓ Found live session TEID: {teid}")
                                
                                completed += 1
                                progress.update(
                                    task,
                                    advance=1,
                                    active=len(active_teids),
                                    live=len(live_sessions)
                                )
                            except Exception as e:
                                completed += 1
                                progress.update(task, advance=1)
                                logger.debug(f"Future error: {e}")
            else:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(probe_teid, upf_ip, teid, timeout, iface, verifier): teid 
                              for teid in range(start_teid, end_teid)}
                    
                    for future in as_completed(futures):
                        try:
                            result = future.result(timeout=timeout + 1)
                            if result:
                                teid, status, _ = result
                                if status == "active":
                                    active_teids.append(teid)
                                    logger.info(f"✓ Found active TEID: {teid}")
                                elif status == "live_session":
                                    live_sessions.append(teid)
                                    logger.info(f"✓ Found live session TEID: {teid}")
                        except Exception as e:
                            logger.debug(f"Future error: {e}")
        else:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TextColumn("Active: {task.fields[active]} | Live: {task.fields[live]}"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]TEID Enumeration",
                        total=total_range,
                        active=0,
                        live=0
                    )
                    
                    for teid in range(start_teid, end_teid):
                        try:
                            result = probe_teid(upf_ip, teid, timeout, iface, verifier)
                            if result:
                                teid_val, status, _ = result
                                if status == "active":
                                    active_teids.append(teid_val)
                                    logger.info(f"✓ Found active TEID: {teid_val}")
                                elif status == "live_session":
                                    live_sessions.append(teid_val)
                                    logger.info(f"✓ Found live session TEID: {teid_val}")
                            
                            progress.update(
                                task,
                                advance=1,
                                active=len(active_teids),
                                live=len(live_sessions)
                            )
                            time.sleep(delay)
                        except KeyboardInterrupt:
                            logger.warning("Enumeration interrupted")
                            break
                        except Exception as e:
                            logger.debug(f"Error at TEID {teid}: {e}")
                            progress.update(task, advance=1)
            else:
                for teid in range(start_teid, end_teid):
                    try:
                        result = probe_teid(upf_ip, teid, timeout, iface, verifier)
                        if result:
                            teid_val, status, _ = result
                            if status == "active":
                                active_teids.append(teid_val)
                                logger.info(f"✓ Found active TEID: {teid_val}")
                            elif status == "live_session":
                                live_sessions.append(teid_val)
                                logger.info(f"✓ Found live session TEID: {teid_val}")
                        time.sleep(delay)
                    except KeyboardInterrupt:
                        logger.warning("Enumeration interrupted")
                        break
                    except Exception as e:
                        logger.debug(f"Error at TEID {teid}: {e}")
        
        logger.info(f"Enumeration complete: {len(active_teids)} active, {len(live_sessions)} live sessions")
        return {
            "active": active_teids,
            "live_sessions": live_sessions,
            "total_probed": total_range,
            "success_rate": (len(active_teids) + len(live_sessions)) / total_range * 100 if total_range > 0 else 0
        }
    except KeyboardInterrupt:
        logger.warning("Enumeration interrupted by user")
        return {"active": active_teids, "live_sessions": live_sessions, "interrupted": True}
    except Exception as e:
        logger.error(f"TEID enumeration failed: {e}", exc_info=True)
        return {"active": active_teids, "live_sessions": live_sessions, "error": str(e)}
 
def probe_seid(smf_ip, seid, timeout, iface, verifier=None):
    import socket
    
    try:
        pkt = IP(dst=smf_ip) / UDP(dport=8805) / PFCPHeader(version=1, seid=seid, message_type=1)
        resp = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
        
        if resp:
            if verifier:
                verification = verifier.verify_pfcp_response(resp, expected_seid=seid)
                if verification.get("success"):
                    return (seid, verification)
            
            if resp.haslayer(PFCPHeader):
                if resp[PFCPHeader].message_type == 2:
                    return (seid, {"message_type": 2})
    except socket.timeout:
        return None
    except ConnectionError as e:
        logger.debug(f"Connection error probing SEID {seid}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Error probing SEID {seid}: {e}")
        return None
    return None

def enumerate_seid(smf_ip, start_seid=None, end_seid=None, iface=None, parallel=False, workers=10, show_progress=True):
    if iface is None:
        iface = TEST_CONFIG["interface"]
    if start_seid is None:
        start_seid = TEST_CONFIG["seid_range"][0]
    if end_seid is None:
        end_seid = TEST_CONFIG["seid_range"][1]
    
    validate_config()
    active_seids = []
    timeout = TEST_CONFIG["enum_timeout"]
    delay = TEST_CONFIG["enum_delay"]
    verifier = ResponseVerifier(timeout=timeout)
    
    total_range = end_seid - start_seid
    logger.info(f"Enumerating SEIDs from {start_seid} to {end_seid} on {smf_ip} ({total_range} SEIDs)")
    
    console = Console() if show_progress else None
    
    try:
        if parallel:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("Active: {task.fields[active]}"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]SEID Enumeration",
                        total=total_range,
                        active=0
                    )
                    
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        futures = {executor.submit(probe_seid, smf_ip, seid, timeout, iface, verifier): seid 
                                  for seid in range(start_seid, end_seid)}
                        
                        for future in as_completed(futures):
                            try:
                                result = future.result(timeout=timeout + 1)
                                if result:
                                    seid_val, _ = result
                                    active_seids.append(seid_val)
                                    logger.info(f"✓ Found active SEID: {seid_val}")
                                
                                progress.update(
                                    task,
                                    advance=1,
                                    active=len(active_seids)
                                )
                            except Exception as e:
                                progress.update(task, advance=1)
                                logger.debug(f"Future error: {e}")
            else:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(probe_seid, smf_ip, seid, timeout, iface, verifier): seid 
                              for seid in range(start_seid, end_seid)}
                    
                    for future in as_completed(futures):
                        try:
                            result = future.result(timeout=timeout + 1)
                            if result:
                                seid_val, _ = result
                                active_seids.append(seid_val)
                                logger.info(f"✓ Found active SEID: {seid_val}")
                        except Exception as e:
                            logger.debug(f"Future error: {e}")
        else:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TextColumn("Active: {task.fields[active]}"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]SEID Enumeration",
                        total=total_range,
                        active=0
                    )
                    
                    for seid in range(start_seid, end_seid):
                        try:
                            result = probe_seid(smf_ip, seid, timeout, iface, verifier)
                            if result:
                                seid_val, _ = result
                                active_seids.append(seid_val)
                                logger.info(f"✓ Found active SEID: {seid_val}")
                            
                            progress.update(
                                task,
                                advance=1,
                                active=len(active_seids)
                            )
                            time.sleep(delay)
                        except KeyboardInterrupt:
                            logger.warning("Enumeration interrupted")
                            break
                        except Exception as e:
                            logger.debug(f"Error at SEID {seid}: {e}")
                            progress.update(task, advance=1)
            else:
                for seid in range(start_seid, end_seid):
                    try:
                        result = probe_seid(smf_ip, seid, timeout, iface, verifier)
                        if result:
                            seid_val, _ = result
                            active_seids.append(seid_val)
                            logger.info(f"✓ Found active SEID: {seid_val}")
                        time.sleep(delay)
                    except KeyboardInterrupt:
                        logger.warning("Enumeration interrupted")
                        break
                    except Exception as e:
                        logger.debug(f"Error at SEID {seid}: {e}")
        
        logger.info(f"Enumeration complete: {len(active_seids)} active SEIDs")
        return {
            "active": active_seids,
            "total_probed": total_range,
            "success_rate": len(active_seids) / total_range * 100 if total_range > 0 else 0
        }
    except KeyboardInterrupt:
        logger.warning("Enumeration interrupted by user")
        return {"active": active_seids, "interrupted": True}
    except Exception as e:
        logger.error(f"SEID enumeration failed: {e}", exc_info=True)
        return {"active": active_seids, "error": str(e)}

if __name__ == "__main__":
    logger.info("Starting TEID/SEID enumeration test")
    teids = enumerate_teid(TEST_CONFIG["upf_ip"], parallel=True)
    logger.info(f"Active TEIDs: {teids}")
    
    seids = enumerate_seid(TEST_CONFIG["smf_ip"], parallel=True)
    logger.info(f"Active SEIDs: {seids}")

