#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SessionState(Enum):
    INITIALIZING = "initializing"
    AUTHENTICATING = "authenticating"
    REGISTERED = "registered"
    CONNECTED = "connected"
    IDLE = "idle"
    HANDOVER = "handover"
    DEREGISTERING = "deregistering"
    TERMINATED = "terminated"


class PDUSessionState(Enum):
    INACTIVE = "inactive"
    PENDING = "pending"
    ACTIVE = "active"
    MODIFYING = "modifying"
    RELEASING = "releasing"
    RELEASED = "released"


@dataclass
class GTPTunnel:
    teid: int
    peer_teid: int
    local_ip: str
    peer_ip: str
    created_at: float
    last_activity: float = 0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    qfi: int = 0


@dataclass
class PDUSession:
    session_id: int
    dnn: str
    slice_id: str
    state: PDUSessionState
    ue_ip: str
    upf_ip: str
    created_at: float
    tunnels: List[GTPTunnel] = field(default_factory=list)
    qos_flows: Dict[int, Dict] = field(default_factory=dict)
    last_activity: float = 0
    total_uplink_bytes: int = 0
    total_downlink_bytes: int = 0


@dataclass
class UESession:
    supi: str
    imei: Optional[str]
    state: SessionState
    amf_id: str
    gnb_id: str
    cell_id: str
    registration_time: float
    last_activity: float
    pdu_sessions: Dict[int, PDUSession] = field(default_factory=dict)
    mobility_events: List[Dict] = field(default_factory=list)
    security_context: Dict = field(default_factory=dict)
    location_history: List[Dict] = field(default_factory=list)


class Session5GTracker:
    def __init__(self, session_timeout: int = 3600):
        self.session_timeout = session_timeout
        self.ue_sessions: Dict[str, UESession] = {}
        self.teid_to_session: Dict[int, str] = {}
        self.ip_to_session: Dict[str, str] = {}
        self.gnb_sessions: Dict[str, Set[str]] = defaultdict(set)
        self.amf_sessions: Dict[str, Set[str]] = defaultdict(set)
        self.slice_sessions: Dict[str, Set[str]] = defaultdict(set)
        self.events: List[Dict] = []
        
    def register_ue(self, supi: str, imei: Optional[str] = None, amf_id: str = "", 
                    gnb_id: str = "", cell_id: str = "") -> UESession:
        now = time.time()
        
        if supi in self.ue_sessions:
            session = self.ue_sessions[supi]
            session.state = SessionState.REGISTERED
            session.last_activity = now
            self._log_event("re_registration", supi, {"previous_state": session.state.value})
        else:
            session = UESession(
                supi=supi,
                imei=imei,
                state=SessionState.REGISTERED,
                amf_id=amf_id,
                gnb_id=gnb_id,
                cell_id=cell_id,
                registration_time=now,
                last_activity=now
            )
            self.ue_sessions[supi] = session
            self._log_event("registration", supi, {"amf": amf_id, "gnb": gnb_id})
        
        self.gnb_sessions[gnb_id].add(supi)
        self.amf_sessions[amf_id].add(supi)
        
        return session
    
    def establish_pdu_session(self, supi: str, session_id: int, dnn: str, 
                              slice_id: str, ue_ip: str, upf_ip: str) -> Optional[PDUSession]:
        if supi not in self.ue_sessions:
            logger.warning(f"UE {supi} not registered")
            return None
        
        ue = self.ue_sessions[supi]
        now = time.time()
        
        pdu = PDUSession(
            session_id=session_id,
            dnn=dnn,
            slice_id=slice_id,
            state=PDUSessionState.ACTIVE,
            ue_ip=ue_ip,
            upf_ip=upf_ip,
            created_at=now,
            last_activity=now
        )
        
        ue.pdu_sessions[session_id] = pdu
        ue.state = SessionState.CONNECTED
        ue.last_activity = now
        
        self.ip_to_session[ue_ip] = supi
        self.slice_sessions[slice_id].add(supi)
        
        self._log_event("pdu_establishment", supi, {
            "session_id": session_id,
            "dnn": dnn,
            "ue_ip": ue_ip
        })
        
        return pdu
    
    def add_tunnel(self, supi: str, session_id: int, teid: int, peer_teid: int,
                   local_ip: str, peer_ip: str, qfi: int = 0) -> Optional[GTPTunnel]:
        if supi not in self.ue_sessions:
            return None
        
        ue = self.ue_sessions[supi]
        if session_id not in ue.pdu_sessions:
            return None
        
        pdu = ue.pdu_sessions[session_id]
        now = time.time()
        
        tunnel = GTPTunnel(
            teid=teid,
            peer_teid=peer_teid,
            local_ip=local_ip,
            peer_ip=peer_ip,
            created_at=now,
            last_activity=now,
            qfi=qfi
        )
        
        pdu.tunnels.append(tunnel)
        self.teid_to_session[teid] = supi
        
        self._log_event("tunnel_created", supi, {
            "session_id": session_id,
            "teid": teid,
            "peer_teid": peer_teid
        })
        
        return tunnel
    
    def record_traffic(self, teid: int, bytes_count: int, direction: str = "uplink"):
        if teid not in self.teid_to_session:
            return
        
        supi = self.teid_to_session[teid]
        if supi not in self.ue_sessions:
            return
        
        ue = self.ue_sessions[supi]
        now = time.time()
        ue.last_activity = now
        
        for pdu in ue.pdu_sessions.values():
            for tunnel in pdu.tunnels:
                if tunnel.teid == teid:
                    tunnel.last_activity = now
                    if direction == "uplink":
                        tunnel.packets_sent += 1
                        tunnel.bytes_sent += bytes_count
                        pdu.total_uplink_bytes += bytes_count
                    else:
                        tunnel.packets_received += 1
                        tunnel.bytes_received += bytes_count
                        pdu.total_downlink_bytes += bytes_count
                    pdu.last_activity = now
                    return
    
    def handover(self, supi: str, new_gnb_id: str, new_cell_id: str) -> bool:
        if supi not in self.ue_sessions:
            return False
        
        ue = self.ue_sessions[supi]
        old_gnb = ue.gnb_id
        old_cell = ue.cell_id
        now = time.time()
        
        ue.state = SessionState.HANDOVER
        
        if old_gnb in self.gnb_sessions:
            self.gnb_sessions[old_gnb].discard(supi)
        
        ue.gnb_id = new_gnb_id
        ue.cell_id = new_cell_id
        self.gnb_sessions[new_gnb_id].add(supi)
        
        ue.mobility_events.append({
            "timestamp": now,
            "type": "handover",
            "from_gnb": old_gnb,
            "from_cell": old_cell,
            "to_gnb": new_gnb_id,
            "to_cell": new_cell_id
        })
        
        ue.location_history.append({
            "timestamp": now,
            "gnb_id": new_gnb_id,
            "cell_id": new_cell_id
        })
        
        ue.state = SessionState.CONNECTED
        ue.last_activity = now
        
        self._log_event("handover", supi, {
            "from_gnb": old_gnb,
            "to_gnb": new_gnb_id
        })
        
        return True
    
    def release_pdu_session(self, supi: str, session_id: int) -> bool:
        if supi not in self.ue_sessions:
            return False
        
        ue = self.ue_sessions[supi]
        if session_id not in ue.pdu_sessions:
            return False
        
        pdu = ue.pdu_sessions[session_id]
        pdu.state = PDUSessionState.RELEASED
        
        for tunnel in pdu.tunnels:
            if tunnel.teid in self.teid_to_session:
                del self.teid_to_session[tunnel.teid]
        
        if pdu.ue_ip in self.ip_to_session:
            del self.ip_to_session[pdu.ue_ip]
        
        self._log_event("pdu_release", supi, {"session_id": session_id})
        
        del ue.pdu_sessions[session_id]
        
        if not ue.pdu_sessions:
            ue.state = SessionState.IDLE
        
        return True
    
    def deregister_ue(self, supi: str) -> bool:
        if supi not in self.ue_sessions:
            return False
        
        ue = self.ue_sessions[supi]
        ue.state = SessionState.DEREGISTERING
        
        for session_id in list(ue.pdu_sessions.keys()):
            self.release_pdu_session(supi, session_id)
        
        self.gnb_sessions[ue.gnb_id].discard(supi)
        self.amf_sessions[ue.amf_id].discard(supi)
        
        for slice_id in self.slice_sessions:
            self.slice_sessions[slice_id].discard(supi)
        
        ue.state = SessionState.TERMINATED
        
        self._log_event("deregistration", supi, {})
        
        return True
    
    def _log_event(self, event_type: str, supi: str, details: Dict):
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "supi": supi,
            "details": details
        }
        self.events.append(event)
        logger.info(f"[{event_type.upper()}] {supi}: {details}")
    
    def cleanup_stale_sessions(self):
        now = time.time()
        stale = []
        
        for supi, ue in self.ue_sessions.items():
            if now - ue.last_activity > self.session_timeout:
                stale.append(supi)
        
        for supi in stale:
            logger.info(f"Cleaning up stale session: {supi}")
            self.deregister_ue(supi)
        
        return len(stale)
    
    def get_session_by_teid(self, teid: int) -> Optional[UESession]:
        if teid not in self.teid_to_session:
            return None
        return self.ue_sessions.get(self.teid_to_session[teid])
    
    def get_session_by_ip(self, ip: str) -> Optional[UESession]:
        if ip not in self.ip_to_session:
            return None
        return self.ue_sessions.get(self.ip_to_session[ip])
    
    def get_gnb_load(self, gnb_id: str) -> Dict:
        sessions = self.gnb_sessions.get(gnb_id, set())
        active = sum(1 for s in sessions if s in self.ue_sessions and self.ue_sessions[s].state == SessionState.CONNECTED)
        
        return {
            "gnb_id": gnb_id,
            "total_sessions": len(sessions),
            "active_sessions": active,
            "session_ids": list(sessions)
        }
    
    def get_slice_statistics(self, slice_id: str) -> Dict:
        sessions = self.slice_sessions.get(slice_id, set())
        
        total_uplink = 0
        total_downlink = 0
        
        for supi in sessions:
            ue = self.ue_sessions.get(supi)
            if ue:
                for pdu in ue.pdu_sessions.values():
                    if pdu.slice_id == slice_id:
                        total_uplink += pdu.total_uplink_bytes
                        total_downlink += pdu.total_downlink_bytes
        
        return {
            "slice_id": slice_id,
            "active_sessions": len(sessions),
            "total_uplink_bytes": total_uplink,
            "total_downlink_bytes": total_downlink
        }
    
    def get_statistics(self) -> Dict:
        active_ues = sum(1 for ue in self.ue_sessions.values() 
                        if ue.state in [SessionState.CONNECTED, SessionState.IDLE])
        
        total_pdu_sessions = sum(len(ue.pdu_sessions) for ue in self.ue_sessions.values())
        
        total_tunnels = sum(
            len(pdu.tunnels) 
            for ue in self.ue_sessions.values() 
            for pdu in ue.pdu_sessions.values()
        )
        
        states = defaultdict(int)
        for ue in self.ue_sessions.values():
            states[ue.state.value] += 1
        
        return {
            "total_ue_sessions": len(self.ue_sessions),
            "active_ue_sessions": active_ues,
            "total_pdu_sessions": total_pdu_sessions,
            "total_tunnels": total_tunnels,
            "active_gnbs": len([g for g, s in self.gnb_sessions.items() if s]),
            "active_slices": len([s for s, sessions in self.slice_sessions.items() if sessions]),
            "session_states": dict(states)
        }
    
    def export_sessions(self, filename: str = "session_data.json"):
        data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "sessions": [],
            "events": self.events[-100:]
        }
        
        for supi, ue in self.ue_sessions.items():
            session_data = {
                "supi": supi,
                "imei": ue.imei,
                "state": ue.state.value,
                "amf_id": ue.amf_id,
                "gnb_id": ue.gnb_id,
                "cell_id": ue.cell_id,
                "registration_time": ue.registration_time,
                "last_activity": ue.last_activity,
                "pdu_sessions": []
            }
            
            for pdu_id, pdu in ue.pdu_sessions.items():
                pdu_data = {
                    "session_id": pdu_id,
                    "dnn": pdu.dnn,
                    "slice_id": pdu.slice_id,
                    "state": pdu.state.value,
                    "ue_ip": pdu.ue_ip,
                    "upf_ip": pdu.upf_ip,
                    "uplink_bytes": pdu.total_uplink_bytes,
                    "downlink_bytes": pdu.total_downlink_bytes,
                    "tunnels": [
                        {
                            "teid": t.teid,
                            "peer_teid": t.peer_teid,
                            "qfi": t.qfi,
                            "bytes_sent": t.bytes_sent,
                            "bytes_received": t.bytes_received
                        }
                        for t in pdu.tunnels
                    ]
                }
                session_data["pdu_sessions"].append(pdu_data)
            
            data["sessions"].append(session_data)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Session data exported to {filename}")
        return filename
    
    def detect_anomalies(self) -> List[Dict]:
        anomalies = []
        now = time.time()
        
        for supi, ue in self.ue_sessions.items():
            if len(ue.mobility_events) > 10:
                recent = [e for e in ue.mobility_events if now - e["timestamp"] < 300]
                if len(recent) > 5:
                    anomalies.append({
                        "type": "excessive_handovers",
                        "severity": "MEDIUM",
                        "supi": supi,
                        "handover_count": len(recent),
                        "description": f"UE performed {len(recent)} handovers in 5 minutes"
                    })
            
            total_bytes = sum(
                pdu.total_uplink_bytes + pdu.total_downlink_bytes 
                for pdu in ue.pdu_sessions.values()
            )
            session_duration = now - ue.registration_time
            if session_duration > 60 and total_bytes / session_duration > 100_000_000:
                anomalies.append({
                    "type": "high_bandwidth_usage",
                    "severity": "LOW",
                    "supi": supi,
                    "bytes_per_second": total_bytes / session_duration,
                    "description": "Unusually high bandwidth consumption"
                })
        
        for gnb_id, sessions in self.gnb_sessions.items():
            if len(sessions) > 1000:
                anomalies.append({
                    "type": "gnb_overload",
                    "severity": "HIGH",
                    "gnb_id": gnb_id,
                    "session_count": len(sessions),
                    "description": f"gNodeB handling {len(sessions)} sessions"
                })
        
        return anomalies


def demo_session_tracking():
    logger.info("Running session tracking demo...")
    
    tracker = Session5GTracker()
    
    for i in range(5):
        supi = f"imsi-00101000000000{i:02d}"
        tracker.register_ue(
            supi=supi,
            imei=f"35678{i:010d}",
            amf_id="amf-001",
            gnb_id=f"gnb-{i % 2 + 1:03d}",
            cell_id=f"cell-{i:03d}"
        )
        
        tracker.establish_pdu_session(
            supi=supi,
            session_id=1,
            dnn="internet",
            slice_id="slice-1",
            ue_ip=f"10.45.0.{i + 1}",
            upf_ip="192.168.100.1"
        )
        
        tracker.add_tunnel(
            supi=supi,
            session_id=1,
            teid=1000 + i,
            peer_teid=2000 + i,
            local_ip="192.168.100.1",
            peer_ip=f"10.0.0.{i + 1}",
            qfi=1
        )
    
    for i in range(100):
        teid = 1000 + (i % 5)
        direction = "uplink" if i % 2 == 0 else "downlink"
        tracker.record_traffic(teid, 1500, direction)
    
    tracker.handover("imsi-001010000000000", "gnb-003", "cell-010")
    tracker.handover("imsi-001010000000000", "gnb-004", "cell-011")
    
    stats = tracker.get_statistics()
    logger.info("\n" + "="*50)
    logger.info("SESSION TRACKING STATISTICS")
    logger.info("="*50)
    logger.info(f"Total UE Sessions: {stats['total_ue_sessions']}")
    logger.info(f"Active Sessions: {stats['active_ue_sessions']}")
    logger.info(f"PDU Sessions: {stats['total_pdu_sessions']}")
    logger.info(f"Active Tunnels: {stats['total_tunnels']}")
    
    anomalies = tracker.detect_anomalies()
    if anomalies:
        logger.warning(f"\nAnomalies: {len(anomalies)}")
        for a in anomalies:
            logger.warning(f"  [{a['severity']}] {a['type']}: {a['description']}")
    
    tracker.export_sessions()
    
    return tracker


def get_session_duration(session: UESession) -> Tuple[float, timedelta]:
    duration_seconds = time.time() - session.registration_time
    duration_td = timedelta(seconds=duration_seconds)
    return duration_seconds, duration_td


def get_expired_sessions(tracker: Session5GTracker, max_age_seconds: int = 3600) -> List[Tuple[str, UESession]]:
    expired = []
    cutoff = time.time() - max_age_seconds
    for supi, session in tracker.ue_sessions.items():
        if session.last_activity < cutoff:
            expired.append((supi, session))
    return expired


if __name__ == "__main__":
    demo_session_tracking()

