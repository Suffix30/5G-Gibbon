#!/usr/bin/env python3
import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager
import logging
 
logger = logging.getLogger(__name__)

class ResultsDatabase:
    def __init__(self, db_path="results/5g_gibbon.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    target_ip TEXT,
                    success INTEGER,
                    packets_sent INTEGER,
                    responses_received INTEGER,
                    keys_extracted TEXT,
                    vulnerabilities TEXT,
                    duration REAL,
                    raw_data TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovered_components (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    component_type TEXT NOT NULL,
                    services TEXT,
                    confidence INTEGER,
                    verified INTEGER
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS extracted_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_vector TEXT,
                    key_type TEXT,
                    imsi TEXT,
                    key_value TEXT,
                    source TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    audit_name TEXT,
                    severity TEXT,
                    finding_type TEXT,
                    description TEXT,
                    component TEXT,
                    recommendation TEXT
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_attack_timestamp ON attack_results(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_components_ip ON discovered_components(ip)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_keys_type ON extracted_keys(key_type)
            """)
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def save_attack_result(self, attack_type, target_ip=None, success=None, 
                          packets_sent=0, responses_received=0, keys_extracted=None,
                          vulnerabilities=None, duration=0, raw_data=None):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO attack_results 
                (timestamp, attack_type, target_ip, success, packets_sent, 
                 responses_received, keys_extracted, vulnerabilities, duration, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                attack_type,
                target_ip,
                1 if success else 0,
                packets_sent,
                responses_received,
                json.dumps(keys_extracted) if keys_extracted else None,
                json.dumps(vulnerabilities) if vulnerabilities else None,
                duration,
                json.dumps(raw_data) if raw_data else None
            ))
    
    def save_component(self, ip, component_type, services=None, confidence=0, verified=False):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO discovered_components 
                (timestamp, ip, component_type, services, confidence, verified)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                ip,
                component_type,
                json.dumps(services) if services else None,
                confidence,
                1 if verified else 0
            ))
    
    def save_extracted_key(self, key_type, key_value, imsi=None, attack_vector=None, source=None):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO extracted_keys 
                (timestamp, key_type, key_value, imsi, attack_vector, source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                key_type,
                key_value,
                imsi,
                attack_vector,
                source
            ))
    
    def get_recent_attacks(self, limit=100):
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM attack_results 
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self):
        with self.get_connection() as conn:
            stats = {}
            
            cursor = conn.execute("SELECT COUNT(*) as total FROM attack_results")
            stats['total_attacks'] = cursor.fetchone()['total']
            
            cursor = conn.execute("SELECT COUNT(*) as total FROM discovered_components")
            stats['total_components'] = cursor.fetchone()['total']
            
            cursor = conn.execute("SELECT COUNT(*) as total FROM extracted_keys")
            stats['total_keys'] = cursor.fetchone()['total']
            
            cursor = conn.execute("""
                SELECT attack_type, COUNT(*) as count 
                FROM attack_results 
                GROUP BY attack_type
            """)
            stats['attacks_by_type'] = {row['attack_type']: row['count'] for row in cursor.fetchall()}
            
            return stats
    
    def get_all_components(self):
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM discovered_components ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_all_findings(self):
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM audit_findings ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def save_audit_finding(self, audit_name, severity, finding_type, description, 
                           component=None, recommendation=None):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO audit_findings 
                (timestamp, audit_name, severity, finding_type, description, component, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                audit_name,
                severity,
                finding_type,
                description,
                component,
                recommendation
            ))
    
    def generate_html_report(self, output_file="session_report.html"):
        from reporting.html_report import (
            ReportGenerator, Finding, SeverityLevel, ScanResult, AttackResult
        )
        
        report = ReportGenerator()
        
        attacks = self.get_recent_attacks(limit=500)
        components = self.get_all_components()
        findings = self.get_all_findings()
        stats = self.get_statistics()
        
        if attacks:
            total_attacks = stats.get("total_attacks", len(attacks))
            success_rate = stats.get("success_rate", 0)
            report.set_metadata(
                title=f"5G-Gibbon Security Assessment Report ({total_attacks} attacks, {success_rate:.1f}% success)",
                assessment_type="Automated Security Assessment",
                target_network="Multiple Targets",
                start_time=attacks[-1].get("timestamp", ""),
                end_time=attacks[0].get("timestamp", "")
            )
        
        for f in findings:
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO
            }
            finding = Finding(
                title=f.get("finding_type", "Unknown Finding"),
                severity=severity_map.get(f.get("severity", "medium").lower(), SeverityLevel.MEDIUM),
                description=f.get("description", ""),
                affected_component=f.get("component", "Unknown"),
                remediation=f.get("recommendation", "Review and address finding")
            )
            report.add_finding(finding)
        
        for c in components:
            services = json.loads(c.get("services", "[]") or "[]")
            service_names = ", ".join(services) if services else c.get("component_type", "Unknown")
            scan_result = ScanResult(
                target=c.get("ip", "Unknown"),
                port=services[0] if services and isinstance(services[0], int) else 0,
                service=service_names,
                state="open" if c.get("verified") else "detected",
                banner=f"Confidence: {c.get('confidence', 0)}% | Services: {len(services)}",
                vulnerabilities=[]
            )
            report.add_scan_result(scan_result)
        
        for a in attacks:
            vulns = json.loads(a.get("vulnerabilities", "[]") or "[]")
            attack_result = AttackResult(
                attack_type=a.get("attack_type", "Unknown"),
                target=a.get("target_ip", "Unknown"),
                success=bool(a.get("success")),
                timestamp=a.get("timestamp", ""),
                duration=a.get("duration", 0) or 0,
                details={
                    "packets_sent": a.get("packets_sent", 0),
                    "responses_received": a.get("responses_received", 0),
                    "keys_extracted": json.loads(a.get("keys_extracted", "null") or "null"),
                    "vulnerabilities": vulns
                }
            )
            report.add_attack_result(attack_result)
        
        path = report.generate_html(output_file)
        logger.info(f"Report generated: {path}")
        return path
    
    def generate_json_report(self, output_file="session_report.json"):
        from reporting.html_report import (
            ReportGenerator, Finding, SeverityLevel, ScanResult, AttackResult
        )
        
        report = ReportGenerator()
        
        attacks = self.get_recent_attacks(limit=500)
        components = self.get_all_components()
        findings = self.get_all_findings()
        
        if attacks:
            report.set_metadata(
                title="5G-Gibbon Security Assessment Report",
                assessment_type="Automated Security Assessment",
                target_network="Multiple Targets",
                start_time=attacks[-1].get("timestamp", ""),
                end_time=attacks[0].get("timestamp", "")
            )
        
        for f in findings:
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO
            }
            finding = Finding(
                title=f.get("finding_type", "Unknown Finding"),
                severity=severity_map.get(f.get("severity", "medium").lower(), SeverityLevel.MEDIUM),
                description=f.get("description", ""),
                affected_component=f.get("component", "Unknown"),
                remediation=f.get("recommendation", "Review and address finding")
            )
            report.add_finding(finding)
        
        for c in components:
            scan_result = ScanResult(
                target=c.get("ip", "Unknown"),
                port=0,
                service=c.get("component_type", "Unknown"),
                state="open" if c.get("verified") else "detected",
                banner=f"Confidence: {c.get('confidence', 0)}%",
                vulnerabilities=[]
            )
            report.add_scan_result(scan_result)
        
        for a in attacks:
            attack_result = AttackResult(
                attack_type=a.get("attack_type", "Unknown"),
                target=a.get("target_ip", "Unknown"),
                success=bool(a.get("success")),
                timestamp=a.get("timestamp", ""),
                duration=a.get("duration", 0) or 0,
                details={
                    "packets_sent": a.get("packets_sent", 0),
                    "responses_received": a.get("responses_received", 0)
                }
            )
            report.add_attack_result(attack_result)
        
        path = report.generate_json(output_file)
        logger.info(f"JSON report generated: {path}")
        return path

