import struct
import socket
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
 
logger = logging.getLogger(__name__)

class S1APProcedureCode(IntEnum):
    ID_HANDOVER_PREPARATION = 0
    ID_HANDOVER_RESOURCE_ALLOCATION = 1
    ID_HANDOVER_NOTIFICATION = 2
    ID_PATH_SWITCH_REQUEST = 3
    ID_HANDOVER_CANCEL = 4
    ID_E_RAB_SETUP = 5
    ID_E_RAB_MODIFY = 6
    ID_E_RAB_RELEASE = 7
    ID_E_RAB_RELEASE_INDICATION = 8
    ID_INITIAL_CONTEXT_SETUP = 9
    ID_PAGING = 10
    ID_DOWNLINK_NAS_TRANSPORT = 11
    ID_INITIAL_UE_MESSAGE = 12
    ID_UPLINK_NAS_TRANSPORT = 13
    ID_RESET = 14
    ID_ERROR_INDICATION = 15
    ID_NAS_NON_DELIVERY_INDICATION = 16
    ID_S1_SETUP = 17
    ID_UE_CONTEXT_RELEASE_REQUEST = 18
    ID_DOWNLINK_S1_CDMA2000_TUNNELLING = 19
    ID_UPLINK_S1_CDMA2000_TUNNELLING = 20
    ID_UE_CONTEXT_MODIFICATION = 21
    ID_UE_CAPABILITY_INFO_INDICATION = 22
    ID_UE_CONTEXT_RELEASE = 23
    ID_ENB_STATUS_TRANSFER = 24
    ID_MME_STATUS_TRANSFER = 25
    ID_DEACTIVATE_TRACE = 26
    ID_TRACE_START = 27
    ID_TRACE_FAILURE_INDICATION = 28
    ID_ENB_CONFIGURATION_UPDATE = 29
    ID_MME_CONFIGURATION_UPDATE = 30
    ID_LOCATION_REPORTING_CONTROL = 31
    ID_LOCATION_REPORTING_FAILURE_INDICATION = 32
    ID_LOCATION_REPORT = 33
    ID_OVERLOAD_START = 34
    ID_OVERLOAD_STOP = 35
    ID_WRITE_REPLACE_WARNING = 36
    ID_ENB_DIRECT_INFORMATION_TRANSFER = 37
    ID_MME_DIRECT_INFORMATION_TRANSFER = 38
    ID_PRIVATE_MESSAGE = 39
    ID_ENB_CONFIGURATION_TRANSFER = 40
    ID_MME_CONFIGURATION_TRANSFER = 41
    ID_CELL_TRAFFIC_TRACE = 42

class S1APMessageType(IntEnum):
    INITIATING_MESSAGE = 0
    SUCCESSFUL_OUTCOME = 1
    UNSUCCESSFUL_OUTCOME = 2

class S1APCauseRadioNetwork(IntEnum):
    UNSPECIFIED = 0
    TX2RELOCOVERALL_EXPIRY = 1
    SUCCESSFUL_HANDOVER = 2
    RELEASE_DUE_TO_EUTRAN_GENERATED_REASON = 3
    HANDOVER_CANCELLED = 4
    PARTIAL_HANDOVER = 5
    HO_FAILURE_IN_TARGET_EPC_ENB_OR_TARGET_SYSTEM = 6
    HO_TARGET_NOT_ALLOWED = 7
    TS1RELOCOVERALL_EXPIRY = 8
    TS1RELOCPREP_EXPIRY = 9
    CELL_NOT_AVAILABLE = 10
    UNKNOWN_TARGET_ID = 11
    NO_RADIO_RESOURCES_AVAILABLE_IN_TARGET_CELL = 12
    UNKNOWN_MME_UE_S1AP_ID = 13
    UNKNOWN_ENB_UE_S1AP_ID = 14
    UNKNOWN_PAIR_UE_S1AP_ID = 15
    HANDOVER_DESIRABLE_FOR_RADIO_REASON = 16
    TIME_CRITICAL_HANDOVER = 17
    RESOURCE_OPTIMISATION_HANDOVER = 18
    REDUCE_LOAD_IN_SERVING_CELL = 19
    USER_INACTIVITY = 20
    RADIO_CONNECTION_WITH_UE_LOST = 21
    LOAD_BALANCING_TAU_REQUIRED = 22
    CS_FALLBACK_TRIGGERED = 23
    UE_NOT_AVAILABLE_FOR_PS_SERVICE = 24
    RADIO_RESOURCES_NOT_AVAILABLE = 25
    FAILURE_IN_RADIO_INTERFACE_PROCEDURE = 26
    INVALID_QOS_COMBINATION = 27
    INTERRAT_REDIRECTION = 28
    INTERACTION_WITH_OTHER_PROCEDURE = 29
    UNKNOWN_E_RAB_ID = 30
    MULTIPLE_E_RAB_ID_INSTANCES = 31
    ENCRYPTION_AND_OR_INTEGRITY_PROTECTION_ALGORITHMS_NOT_SUPPORTED = 32
    S1_INTRA_SYSTEM_HANDOVER_TRIGGERED = 33
    S1_INTER_SYSTEM_HANDOVER_TRIGGERED = 34
    X2_HANDOVER_TRIGGERED = 35

@dataclass
class S1APMessage:
    procedure_code: int
    message_type: S1APMessageType
    criticality: int = 0
    payload: bytes = b''
    ies: List[Dict[str, Any]] = field(default_factory=list)

class S1APProtocol:
    S1AP_PORT = 36412
    SCTP_PPID_S1AP = 18
    
    def __init__(self):
        self.mme_ue_s1ap_id_counter = 1
        self.enb_ue_s1ap_id_counter = 1
        
    def _encode_length(self, length: int) -> bytes:
        if length < 128:
            return bytes([length])
        elif length < 16384:
            return bytes([0x80 | ((length >> 8) & 0x3F), length & 0xFF])
        else:
            return bytes([0xC0 | ((length >> 16) & 0x3F), (length >> 8) & 0xFF, length & 0xFF])
    
    def _encode_ie(self, ie_id: int, criticality: int, value: bytes) -> bytes:
        ie = struct.pack(">H", ie_id)
        ie += bytes([criticality << 6])
        ie += self._encode_length(len(value))
        ie += value
        return ie
    
    def _encode_integer(self, value: int, bits: int = 32) -> bytes:
        if bits <= 8:
            return bytes([value & 0xFF])
        elif bits <= 16:
            return struct.pack(">H", value & 0xFFFF)
        elif bits <= 32:
            return struct.pack(">I", value & 0xFFFFFFFF)
        else:
            return struct.pack(">Q", value)
    
    def _encode_plmn(self, mcc: str, mnc: str) -> bytes:
        mcc_digits = [int(d) for d in mcc.zfill(3)]
        mnc_digits = [int(d) for d in mnc.zfill(3)]
        plmn = bytes([
            (mcc_digits[1] << 4) | mcc_digits[0],
            (mnc_digits[2] << 4) | mcc_digits[2],
            (mnc_digits[1] << 4) | mnc_digits[0]
        ])
        return plmn
    
    def _encode_tai(self, mcc: str, mnc: str, tac: int) -> bytes:
        plmn = self._encode_plmn(mcc, mnc)
        return plmn + struct.pack(">H", tac)
    
    def _encode_eutran_cgi(self, mcc: str, mnc: str, enb_id: int, cell_id: int) -> bytes:
        plmn = self._encode_plmn(mcc, mnc)
        eci = (enb_id << 8) | (cell_id & 0xFF)
        return plmn + struct.pack(">I", eci)
    
    def craft_s1_setup_request(self, 
                                global_enb_id: int = 0x12345,
                                enb_name: str = "RogueENB",
                                mcc: str = "001",
                                mnc: str = "01",
                                tac: int = 0x0001) -> bytes:
        ies = []
        
        plmn = self._encode_plmn(mcc, mnc)
        global_enb = plmn + bytes([0x00]) + struct.pack(">I", global_enb_id)[:3]
        ies.append(self._encode_ie(59, 0, global_enb))
        
        enb_name_bytes = enb_name.encode('utf-8')[:150]
        ies.append(self._encode_ie(60, 1, bytes([len(enb_name_bytes)]) + enb_name_bytes))
        
        tai = self._encode_tai(mcc, mnc, tac)
        supported_tas = bytes([0x00, 0x01]) + tai + bytes([0x00, 0x01, 0x00])
        ies.append(self._encode_ie(64, 0, supported_tas))
        
        paging_drx = bytes([0x00])
        ies.append(self._encode_ie(137, 1, paging_drx))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_S1_SETUP])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def craft_initial_ue_message(self,
                                  enb_ue_s1ap_id: Optional[int] = None,
                                  nas_pdu: Optional[bytes] = None,
                                  mcc: str = "001",
                                  mnc: str = "01",
                                  tac: int = 0x0001,
                                  enb_id: int = 0x12345,
                                  cell_id: int = 0x01) -> bytes:
        if enb_ue_s1ap_id is None:
            enb_ue_s1ap_id = self.enb_ue_s1ap_id_counter
            self.enb_ue_s1ap_id_counter += 1
        
        if nas_pdu is None:
            nas_pdu = bytes([
                0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x00,
                0x00, 0x00, 0x00, 0x10, 0x02, 0xE0, 0xE0, 0x00,
                0x15, 0x02
            ])
        
        ies = []
        
        ies.append(self._encode_ie(8, 0, self._encode_integer(enb_ue_s1ap_id)))
        
        ies.append(self._encode_ie(26, 0, bytes([len(nas_pdu)]) + nas_pdu))
        
        tai = self._encode_tai(mcc, mnc, tac)
        ies.append(self._encode_ie(67, 0, tai))
        
        eutran_cgi = self._encode_eutran_cgi(mcc, mnc, enb_id, cell_id)
        ies.append(self._encode_ie(100, 1, eutran_cgi))
        
        rrc_cause = bytes([0x00])
        ies.append(self._encode_ie(134, 1, rrc_cause))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_INITIAL_UE_MESSAGE])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def craft_uplink_nas_transport(self,
                                    mme_ue_s1ap_id: int,
                                    enb_ue_s1ap_id: int,
                                    nas_pdu: bytes,
                                    mcc: str = "001",
                                    mnc: str = "01",
                                    tac: int = 0x0001,
                                    enb_id: int = 0x12345,
                                    cell_id: int = 0x01) -> bytes:
        ies = []
        
        ies.append(self._encode_ie(0, 0, self._encode_integer(mme_ue_s1ap_id)))
        ies.append(self._encode_ie(8, 0, self._encode_integer(enb_ue_s1ap_id)))
        ies.append(self._encode_ie(26, 0, bytes([len(nas_pdu)]) + nas_pdu))
        
        eutran_cgi = self._encode_eutran_cgi(mcc, mnc, enb_id, cell_id)
        ies.append(self._encode_ie(100, 1, eutran_cgi))
        
        tai = self._encode_tai(mcc, mnc, tac)
        ies.append(self._encode_ie(67, 0, tai))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_UPLINK_NAS_TRANSPORT])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def craft_handover_required(self,
                                 mme_ue_s1ap_id: int,
                                 enb_ue_s1ap_id: int,
                                 handover_type: int = 0,
                                 cause: int = S1APCauseRadioNetwork.HANDOVER_DESIRABLE_FOR_RADIO_REASON,
                                 target_mcc: str = "001",
                                 target_mnc: str = "01",
                                 target_enb_id: int = 0x54321,
                                 target_tac: int = 0x0002) -> bytes:
        ies = []
        
        ies.append(self._encode_ie(0, 0, self._encode_integer(mme_ue_s1ap_id)))
        ies.append(self._encode_ie(8, 0, self._encode_integer(enb_ue_s1ap_id)))
        
        ies.append(self._encode_ie(1, 1, bytes([handover_type])))
        
        cause_bytes = bytes([0x00, cause])
        ies.append(self._encode_ie(2, 1, cause_bytes))
        
        target_plmn = self._encode_plmn(target_mcc, target_mnc)
        target_id = target_plmn + bytes([0x00]) + struct.pack(">I", target_enb_id)[:3]
        target_id += struct.pack(">H", target_tac)
        ies.append(self._encode_ie(4, 0, target_id))
        
        source_to_target = bytes([0x00] * 20)
        ies.append(self._encode_ie(104, 0, source_to_target))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_HANDOVER_PREPARATION])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def craft_ue_context_release_request(self,
                                          mme_ue_s1ap_id: int,
                                          enb_ue_s1ap_id: int,
                                          cause: int = S1APCauseRadioNetwork.USER_INACTIVITY) -> bytes:
        ies = []
        
        ies.append(self._encode_ie(0, 0, self._encode_integer(mme_ue_s1ap_id)))
        ies.append(self._encode_ie(8, 0, self._encode_integer(enb_ue_s1ap_id)))
        
        cause_bytes = bytes([0x00, cause])
        ies.append(self._encode_ie(2, 1, cause_bytes))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_UE_CONTEXT_RELEASE_REQUEST])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def craft_reset(self, reset_type: str = "s1-interface") -> bytes:
        ies = []
        
        cause_bytes = bytes([0x00, 0x00])
        ies.append(self._encode_ie(2, 1, cause_bytes))
        
        if reset_type == "s1-interface":
            reset_value = bytes([0x00])
        else:
            reset_value = bytes([0x40, 0x00])
        ies.append(self._encode_ie(92, 0, reset_value))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_RESET])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def craft_error_indication(self,
                                mme_ue_s1ap_id: Optional[int] = None,
                                enb_ue_s1ap_id: Optional[int] = None,
                                cause: int = S1APCauseRadioNetwork.UNSPECIFIED) -> bytes:
        ies = []
        
        if mme_ue_s1ap_id is not None:
            ies.append(self._encode_ie(0, 1, self._encode_integer(mme_ue_s1ap_id)))
        
        if enb_ue_s1ap_id is not None:
            ies.append(self._encode_ie(8, 1, self._encode_integer(enb_ue_s1ap_id)))
        
        cause_bytes = bytes([0x00, cause])
        ies.append(self._encode_ie(2, 1, cause_bytes))
        
        ie_container = b''.join(ies)
        num_ies = len(ies)
        
        pdu = bytes([S1APMessageType.INITIATING_MESSAGE])
        pdu += bytes([S1APProcedureCode.ID_ERROR_INDICATION])
        pdu += bytes([0x00])
        pdu += self._encode_length(len(ie_container) + 2)
        pdu += struct.pack(">H", num_ies)
        pdu += ie_container
        
        return pdu
    
    def parse_s1ap_message(self, data: bytes) -> Optional[S1APMessage]:
        if len(data) < 4:
            return None
        
        try:
            msg_type = S1APMessageType(data[0])
            proc_code = data[1]
            criticality = data[2]
            
            return S1APMessage(
                procedure_code=proc_code,
                message_type=msg_type,
                criticality=criticality,
                payload=data[3:]
            )
        except Exception as e:
            logger.error(f"Failed to parse S1AP message: {e}")
            return None
    
    def send_s1ap_message(self, target_ip: str, message: bytes, timeout: float = 5.0) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, self.S1AP_PORT))
            
            sock.send(message)
            
            response = sock.recv(4096)
            sock.close()
            
            return response
        except socket.timeout:
            logger.warning(f"Timeout sending S1AP message to {target_ip}")
            return None
        except Exception as e:
            logger.error(f"Error sending S1AP message: {e}")
            return None
    
    def send_s1ap_message_with_status(self, target_ip: str, message: bytes, timeout: float = 5.0) -> Tuple[bool, Optional[bytes], Optional[str]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, self.S1AP_PORT))
            
            sock.send(message)
            
            response = sock.recv(4096)
            sock.close()
            
            return (True, response, None)
        except socket.timeout:
            return (False, None, f"Timeout connecting to {target_ip}:{self.S1AP_PORT}")
        except socket.error as e:
            return (False, None, f"Socket error: {e}")
        except Exception as e:
            return (False, None, f"Error: {e}")
    
    def encode_plmn(self, mcc: str, mnc: str) -> Tuple[bytes, str]:
        plmn_bytes = self._encode_plmn(mcc, mnc)
        plmn_str = f"{mcc}-{mnc}"
        return (plmn_bytes, plmn_str)


def test_s1ap_setup(mme_ip: str) -> Dict[str, Any]:
    logger.info(f"Testing S1AP Setup against MME: {mme_ip}")
    
    s1ap = S1APProtocol()
    
    setup_request = s1ap.craft_s1_setup_request(
        global_enb_id=0xABCDE,
        enb_name="TestENB",
        mcc="001",
        mnc="01",
        tac=0x0001
    )
    
    logger.info(f"Crafted S1 Setup Request: {len(setup_request)} bytes")
    
    result = {
        "target": mme_ip,
        "message_type": "S1SetupRequest",
        "message_size": len(setup_request),
        "message_hex": setup_request.hex(),
        "response": None,
        "success": False
    }
    
    response = s1ap.send_s1ap_message(mme_ip, setup_request)
    
    if response:
        result["response"] = response.hex()
        result["success"] = True
        parsed = s1ap.parse_s1ap_message(response)
        if parsed:
            result["response_type"] = parsed.message_type.name
            result["response_procedure"] = parsed.procedure_code
    
    return result


def enumerate_mme_ue_ids(mme_ip: str, start_id: int = 1, end_id: int = 100) -> Dict[str, Any]:
    logger.info(f"Enumerating MME UE S1AP IDs on {mme_ip}: {start_id}-{end_id}")
    
    s1ap = S1APProtocol()
    valid_ids = []
    
    for ue_id in range(start_id, end_id + 1):
        error_msg = s1ap.craft_error_indication(
            mme_ue_s1ap_id=ue_id,
            cause=S1APCauseRadioNetwork.UNKNOWN_MME_UE_S1AP_ID
        )
        
        response = s1ap.send_s1ap_message(mme_ip, error_msg, timeout=1.0)
        
        if response:
            parsed = s1ap.parse_s1ap_message(response)
            if parsed and parsed.message_type != S1APMessageType.UNSUCCESSFUL_OUTCOME:
                valid_ids.append(ue_id)
                logger.info(f"  Valid MME UE S1AP ID found: {ue_id}")
    
    return {
        "target": mme_ip,
        "range": f"{start_id}-{end_id}",
        "valid_ids": valid_ids,
        "count": len(valid_ids)
    }

