#!/usr/bin/env python3
"""
5G-Gibbon Security Testing Toolkit
===================================
Interactive mode: python cli.py
Direct mode:      python cli.py <command> [options]
"""

import argparse
import sys
import logging
import os

# Rich imports for interactive mode
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

def load_config():
    """Load configuration from core.config"""
    try:
        from core.config import TEST_CONFIG as cfg
        return cfg
    except ImportError:
        return {
            "upf_ip": "127.0.0.7",
            "amf_ip": "127.0.0.5",
            "smf_ip": "127.0.0.4",
            "interface": "lo",
            "outer_teid": 1,
            "inner_teid": 2,
            "outer_src": "127.0.0.1",
            "inner_src": "10.0.0.1",
            "victim_ip": "10.0.0.100",
            "victim_teid": 9999,
            "attacker_ue_ip": "10.0.0.100",
        }

TEST_CONFIG = load_config()

def is_root():
    """Check if running as root"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

IS_ROOT = is_root()

# ============================================================================
# MENU DEFINITIONS 
# ============================================================================

MAIN_MENU = {
    "1": ("Discovery", "Scan and discover 5G/4G network components"),
    "2": ("Audit", "Run comprehensive security audit"),
    "3": ("Key Extraction", "Extract encryption keys (multiple methods)"),
    "4": ("Attacks", "Individual attack modules"),
    "5": ("Advanced Attacks", "Timing, side-channel, and fuzzing attacks"),
    "6": ("Red Team", "Full offensive attack framework"),
    "7": ("Blue Team", "Defense and remediation"),
    "8": ("Async Operations", "High-performance async scanning/attacks (5-10x faster)"),
    "9": ("Protocol Tools", "HTTP/2 SBI, SCTP/NGAP, Protocol Fuzzing"),
    "L": ("4G/LTE", "4G LTE attacks (S1AP, Diameter, MME, HSS)"),
    "A": ("Reporting", "Generate reports and visualizations"),
    "U": ("Utilities", "Helper tools and configuration"),
    "0": ("Exit", "Exit the toolkit"),
}

LTE_MENU = {
    "1": ("Rogue eNodeB", "Register rogue eNodeB to MME via S1AP"),
    "2": ("Initial UE Injection", "Inject fake Initial UE Message"),
    "3": ("Force Handover", "Force UE handover to rogue eNodeB"),
    "4": ("S1 Reset", "Send S1 Interface Reset to MME"),
    "5": ("HSS Probe", "Probe HSS with Diameter CER"),
    "6": ("IMSI Enumeration", "Enumerate valid IMSIs on HSS"),
    "7": ("Cancel Location", "Send Cancel Location to disconnect UE"),
    "8": ("Auth Vector Extraction", "Extract authentication vectors from HSS"),
    "9": ("Full LTE Assessment", "Run complete 4G/LTE security assessment"),
    "0": ("Back", "Return to main menu"),
}

KEY_EXTRACTION_MENU = {
    "1": ("Standard", "NGAP-based key extraction via gNodeB registration"),
    "2": ("Stress Test", "Multi-phase aggressive stress test"),
    "3": ("Nuclear", "10-vector simultaneous attack"),
    "4": ("Maximum", "Direct database access + all vectors combined"),
    "0": ("Back", "Return to main menu"),
}

ATTACKS_MENU = {
    "1": ("Billing Fraud", "GTP-U billing manipulation attack"),
    "2": ("Nested Tunnels", "Nested GTP-U tunnel attacks (DPI bypass)"),
    "3": ("TEID Enumeration", "Enumerate active tunnel endpoints"),
    "4": ("PFCP Attacks", "PFCP session manipulation"),
    "5": ("UE Injection", "User-to-user traffic injection"),
    "6": ("Rogue gNodeB", "Register rogue base station"),
    "7": ("NGAP Injection", "NGAP protocol injection"),
    "0": ("Back", "Return to main menu"),
}

UTILITIES_MENU = {
    "1": ("Show Config", "Display current configuration"),
    "2": ("Show Status", "Show detected components and status"),
    "3": ("Add Subscriber", "Add test subscriber to database"),
    "4": ("List Subscribers", "List all subscribers in database"),
    "5": ("Packet Capture", "Capture and analyze traffic"),
    "6": ("Rate Limiting Test", "Test network rate limiting"),
    "7": ("Traffic Analyzer", "Deep protocol traffic analysis"),
    "8": ("Session Tracker", "Track UE/PDU sessions"),
    "0": ("Back", "Return to main menu"),
}

ASYNC_MENU = {
    "1": ("Async Network Scan", "Scan network 10x faster with async I/O"),
    "2": ("Async TEID Enum", "Enumerate TEIDs 5x faster (100+ concurrent)"),
    "3": ("Async SEID Enum", "Enumerate SEIDs 5x faster"),
    "4": ("Async Billing Attack", "High-throughput billing fraud"),
    "5": ("Async DoS", "High-rate denial of service"),
    "6": ("Async Nested Tunnel", "Concurrent nested tunnel attack"),
    "0": ("Back", "Return to main menu"),
}

PROTOCOL_MENU = {
    "1": ("SBI Scanner", "Scan for HTTP/2 SBI services (NRF, UDM, AMF...)"),
    "2": ("SBI NF Discovery", "Discover NF instances via NRF"),
    "3": ("Rogue NF Registration", "Register rogue NF via SBI"),
    "4": ("SCTP/NGAP Test", "Test SCTP connection to AMF"),
    "5": ("GTP Fuzzer", "Fuzz GTP-U protocol"),
    "6": ("PFCP Fuzzer", "Fuzz PFCP protocol"),
    "0": ("Back", "Return to main menu"),
}

BLUE_TEAM_MENU = {
    "1": ("Deploy All Defenses", "Apply all defensive measures"),
    "2": ("Apply DPI Rules", "Apply deep packet inspection iptables rules"),
    "3": ("Remove DPI Rules", "Remove DPI iptables rules"),
    "4": ("Verify DPI", "Verify DPI rules are working"),
    "5": ("Show DPI Stats", "Show DPI blocking statistics"),
    "6": ("Full Blue Team", "Run full defense framework with monitoring"),
    "7": ("IDS Signatures", "Generate Snort/Suricata/iptables rules"),
    "8": ("Honeypot Network", "Deploy 5G honeypot decoys"),
    "9": ("Anomaly Detector", "Real-time traffic anomaly detection"),
    "A": ("Security Audit", "Run compliance/security audit"),
    "0": ("Back", "Return to main menu"),
}

ADVANCED_ATTACKS_MENU = {
    "1": ("TEID Oracle", "Timing attack to enumerate valid TEIDs"),
    "2": ("Auth Timing", "Authentication timing side-channel"),
    "3": ("Rate Limit Probe", "Detect rate limiting thresholds"),
    "4": ("Session Oracle", "Session timing attack on PFCP"),
    "5": ("Error Oracle", "Error-based side-channel analysis"),
    "6": ("Traffic Analysis", "Passive traffic pattern analysis"),
    "7": ("Resource Exhaustion", "Probe resource limits"),
    "8": ("Advanced GTP Fuzz", "Grammar-based GTP fuzzing"),
    "9": ("Advanced PFCP Fuzz", "State-aware PFCP fuzzing"),
    "A": ("NGAP Fuzzing", "NGAP protocol fuzzing"),
    "0": ("Back", "Return to main menu"),
}

REPORTING_MENU = {
    "1": ("Generate HTML Report", "Create comprehensive HTML security report"),
    "2": ("Generate JSON Report", "Export results as JSON"),
    "3": ("Network Topology", "Interactive network topology visualization"),
    "4": ("Session Report", "Generate report from all session data"),
    "5": ("Start Dashboard", "Launch real-time attack dashboard"),
    "6": ("Stop Dashboard", "Stop the dashboard server"),
    "0": ("Back", "Return to main menu"),
}

# ============================================================================
# INTERACTIVE MODE (Rich)
# ============================================================================

class InteractiveMode:
    def __init__(self):
        if not RICH_AVAILABLE:
            print("ERROR: Rich library not installed. Install with: pip install rich")
            sys.exit(1)
        self.console = Console()
        
    def clear(self):
        """Clear screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def show_banner(self):
        """Display toolkit banner"""
        banner = r"""
 ____   ____       ____ _ _     _                 
| ___| / ___|     / ___(_) |__ | |__   ___  _ __  
|___ \| |  _ ____| |  _| | '_ \| '_ \ / _ \| '_ \ 
 ___) | |_| |____| |_| | | |_) | |_) | (_) | | | |
|____/ \____|     \____|_|_.__/|_.__/ \___/|_| |_|
                                                   
        5G Security Testing Toolkit
        by NET - Gaspberry
"""
        self.console.print(Panel(banner, style="bold cyan", title="v1.0"))
        
        if not IS_ROOT:
            self.console.print("[yellow]WARNING: Not running as root. Some features may be limited.[/yellow]")
        self.console.print()
        
    def show_menu(self, title, menu_items):
        """Display a menu and get selection"""
        table = Table(show_header=True, header_style="bold white", box=None)
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Name", style="green", width=20)
        table.add_column("Description", style="dim")
        
        for key, (name, desc) in menu_items.items():
            table.add_row(f"[{key}]", name, desc)
        
        self.console.print(Panel(table, title=title, border_style="blue"))
        
        valid_choices = list(menu_items.keys())
        choice = Prompt.ask("Select option", choices=valid_choices, show_choices=False)
        return choice
    
    def confirm_action(self, message):
        """Confirm an action"""
        return Confirm.ask(message)
    
    def get_ip(self, prompt, default):
        """Get IP address input"""
        return Prompt.ask(prompt, default=default)
    
    def get_int(self, prompt, default):
        """Get integer input"""
        return IntPrompt.ask(prompt, default=default)
    
    def show_result(self, title, content, style="green"):
        """Display result in a panel"""
        self.console.print(Panel(content, title=title, border_style=style))
    
    def show_error(self, message):
        """Display error message"""
        self.console.print(f"[red]ERROR: {message}[/red]")
    
    def show_success(self, message):
        """Display success message"""
        self.console.print(f"[green]SUCCESS: {message}[/green]")
        
    def run(self):
        """Main interactive loop"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("MAIN MENU", MAIN_MENU)
            
            if choice == "0":
                self.console.print("[cyan]Goodbye![/cyan]")
                break
            elif choice == "1":
                self.run_discovery()
            elif choice == "2":
                self.run_audit()
            elif choice == "3":
                self.run_key_extraction_menu()
            elif choice == "4":
                self.run_attacks_menu()
            elif choice == "5":
                self.run_advanced_attacks_menu()
            elif choice == "6":
                self.run_red_team()
            elif choice == "7":
                self.run_blue_team_menu()
            elif choice == "8":
                self.run_async_menu()
            elif choice == "9":
                self.run_protocol_menu()
            elif choice.upper() == "L":
                self.run_lte_menu()
            elif choice.upper() == "A":
                self.run_reporting_menu()
            elif choice.upper() == "U":
                self.run_utilities_menu()
    
    def run_discovery(self):
        """Run network discovery"""
        self.console.print("\n[bold]Network Discovery[/bold]\n")
        
        network = self.get_ip("Network range to scan", "127.0.0.0/24")
        
        if self.confirm_action(f"Scan network {network}?"):
            self.console.print("[yellow]Scanning network...[/yellow]")
            # Import and run discovery
            try:
                from discovery.network_discovery import discover_5g_network, display_discovered_network
                components, all_hosts = discover_5g_network(network)
                display_discovered_network(components, all_hosts)
                self.show_success(f"Found {len(components)} components")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_audit(self):
        """Run security audit"""
        self.console.print("\n[bold]Security Audit[/bold]\n")
        
        client = Prompt.ask("Client name for report", default="Test Client")
        
        if self.confirm_action("Run full security audit?"):
            self.console.print("[yellow]Running audit...[/yellow]")
            try:
                from audit.security_audit import run_full_audit
                run_full_audit(client_name=client)
                self.show_success("Audit complete - check output file")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_key_extraction_menu(self):
        """Key extraction submenu"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("KEY EXTRACTION", KEY_EXTRACTION_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_key_standard()
            elif choice == "2":
                self.run_key_stress()
            elif choice == "3":
                self.run_key_nuclear()
            elif choice == "4":
                self.run_key_maximum()
    
    def run_key_standard(self):
        """Standard key extraction"""
        self.console.print("\n[bold]Standard Key Extraction[/bold]\n")
        
        amf_ip = self.get_ip("AMF IP address", TEST_CONFIG["amf_ip"])
        
        if self.confirm_action("Run standard key extraction?"):
            try:
                from key_extraction.ngap_key_extraction import rogue_gnodeb_with_key_extraction
                rogue_gnodeb_with_key_extraction(
                    upf_ip=TEST_CONFIG["upf_ip"],
                    outer_teid=TEST_CONFIG["outer_teid"],
                    amf_ip=amf_ip,
                    inner_teid=TEST_CONFIG["inner_teid"]
                )
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_key_stress(self):
        """Stress test key extraction"""
        self.console.print("\n[bold]Stress Test Key Extraction[/bold]\n")
        self.console.print("[yellow]This will send many packets aggressively[/yellow]")
        
        if self.confirm_action("Run stress test?"):
            try:
                from key_extraction.key_extraction_stress import run_full_stress_test
                run_full_stress_test()
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_key_nuclear(self):
        """Nuclear key extraction"""
        self.console.print("\n[bold]Nuclear Key Extraction[/bold]\n")
        self.console.print("[red]WARNING: This is extremely aggressive[/red]")
        
        if self.confirm_action("Run nuclear extraction?"):
            try:
                from key_extraction.nuclear_key_extraction import NuclearKeyExtraction
                nuke = NuclearKeyExtraction()
                nuke.run_nuclear_extraction()
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_key_maximum(self):
        """Maximum key extraction"""
        self.console.print("\n[bold]Maximum Key Extraction[/bold]\n")
        self.console.print("[red]WARNING: Includes direct database access[/red]")
        
        if self.confirm_action("Run maximum extraction?"):
            try:
                from key_extraction.maximum_extraction import run_maximum
                run_maximum()
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attacks_menu(self):
        """Attacks submenu"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("ATTACKS", ATTACKS_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_attack_billing()
            elif choice == "2":
                self.run_attack_nested()
            elif choice == "3":
                self.run_attack_teid()
            elif choice == "4":
                self.run_attack_pfcp()
            elif choice == "5":
                self.run_attack_ue()
            elif choice == "6":
                self.run_attack_rogue()
            elif choice == "7":
                self.run_attack_ngap()
    
    def run_attack_billing(self):
        """Billing fraud attack"""
        self.console.print("\n[bold]Billing Fraud Attack[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        count = self.get_int("Number of packets", 10)
        
        if self.confirm_action("Run billing fraud attack?"):
            try:
                from attacks.billing_fraud import reflective_injection
                reflective_injection(
                    upf_ip=upf_ip,
                    outer_teid=TEST_CONFIG["outer_teid"],
                    victim_ip=TEST_CONFIG["victim_ip"],
                    victim_teid=TEST_CONFIG["victim_teid"],
                    count=count
                )
                self.show_success("Attack complete")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attack_nested(self):
        """Nested tunnel attack"""
        self.console.print("\n[bold]Nested Tunnel Attack[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        depth = self.get_int("Nesting depth", 3)
        
        if self.confirm_action("Run nested tunnel test?"):
            try:
                from attacks.nested_tunnel_testing import test_nested_depth
                test_nested_depth(upf_ip, max_depth=depth)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attack_teid(self):
        """TEID enumeration"""
        self.console.print("\n[bold]TEID Enumeration[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        start = self.get_int("Start TEID", 0)
        end = self.get_int("End TEID", 1000)
        
        if self.confirm_action("Run TEID enumeration?"):
            try:
                from enumeration.teid_seid_enumeration import enumerate_teid
                enumerate_teid(upf_ip, start, end)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attack_pfcp(self):
        """PFCP attacks"""
        self.console.print("\n[bold]PFCP Attacks[/bold]\n")
        
        smf_ip = self.get_ip("SMF IP", TEST_CONFIG["smf_ip"])
        
        if self.confirm_action("Run PFCP attacks?"):
            try:
                from attacks.pfcp_attacks import pfcp_association_attack
                pfcp_association_attack(smf_ip)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attack_ue(self):
        """UE injection attacks"""
        self.console.print("\n[bold]UE-to-UE Injection[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        victim_ip = self.get_ip("Victim UE IP", TEST_CONFIG["victim_ip"])
        
        if self.confirm_action("Run UE injection attack?"):
            try:
                from attacks.ue_to_ue_injection import battery_drain_attack
                battery_drain_attack(
                    upf_ip=upf_ip,
                    attacker_ue_ip=TEST_CONFIG["attacker_ue_ip"],
                    attacker_teid=TEST_CONFIG["outer_teid"],
                    victim_ue_ip=victim_ip,
                    victim_teid=TEST_CONFIG["victim_teid"]
                )
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attack_rogue(self):
        """Rogue gNodeB"""
        self.console.print("\n[bold]Rogue gNodeB Registration[/bold]\n")
        
        amf_ip = self.get_ip("AMF IP", TEST_CONFIG["amf_ip"])
        
        if self.confirm_action("Attempt rogue gNodeB registration?"):
            try:
                from attacks.rogue_gnodeb import rogue_gnodeb_register
                rogue_gnodeb_register(
                    upf_ip=TEST_CONFIG["upf_ip"],
                    outer_teid=TEST_CONFIG["outer_teid"],
                    amf_ip=amf_ip,
                    inner_teid=TEST_CONFIG["inner_teid"]
                )
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_attack_ngap(self):
        """NGAP injection"""
        self.console.print("\n[bold]NGAP Injection[/bold]\n")
        
        amf_ip = self.get_ip("AMF IP", TEST_CONFIG["amf_ip"])
        
        if self.confirm_action("Run NGAP injection?"):
            try:
                from attacks.ngap_injection import inject_ngap
                inject_ngap(
                    upf_ip=TEST_CONFIG["upf_ip"],
                    outer_teid=TEST_CONFIG["outer_teid"],
                    amf_ip=amf_ip,
                    inner_teid=TEST_CONFIG["inner_teid"]
                )
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_red_team(self):
        """Full red team"""
        self.console.print("\n[bold]ULTRA Red Team[/bold]\n")
        self.console.print("[red]WARNING: This runs ALL attack vectors[/red]\n")
        
        target_ip = Prompt.ask("Target IP", default="127.0.0.1")
        intensity = Prompt.ask("Intensity", choices=["standard", "maximum"], default="maximum")
        
        if self.confirm_action(f"Run ULTRA Red Team against {target_ip} at {intensity} intensity?"):
            try:
                from red_team.ultra_red_team import run_ultra_red_team
                run_ultra_red_team(target_ip=target_ip, intensity=intensity)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_blue_team_menu(self):
        """Blue team submenu"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("BLUE TEAM / DEFENSE", BLUE_TEAM_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_blue_deploy_all()
            elif choice == "2":
                self.run_blue_apply_dpi()
            elif choice == "3":
                self.run_blue_remove_dpi()
            elif choice == "4":
                self.run_blue_verify_dpi()
            elif choice == "5":
                self.run_blue_dpi_stats()
            elif choice == "6":
                self.run_blue_full()
            elif choice == "7":
                self.run_ids_signatures()
            elif choice == "8":
                self.run_honeypot()
            elif choice == "9":
                self.run_anomaly_detector()
            elif choice.upper() == "A":
                self.run_security_audit()
    
    def run_blue_deploy_all(self):
        """Deploy all defenses"""
        self.console.print("\n[bold]Deploy All Defenses[/bold]\n")
        
        if self.confirm_action("Deploy all defensive measures?"):
            try:
                from defense.ultra_blue_team import deploy_defenses_only
                deploy_defenses_only()
                self.show_success("All defenses deployed")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_blue_apply_dpi(self):
        """Apply DPI rules"""
        self.console.print("\n[bold]Apply DPI Rules[/bold]\n")
        
        if self.confirm_action("Apply DPI iptables rules?"):
            try:
                from defense.dpi_remediation import apply_iptables_dpi
                apply_iptables_dpi()
                self.show_success("DPI rules applied")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_blue_remove_dpi(self):
        """Remove DPI rules"""
        self.console.print("\n[bold]Remove DPI Rules[/bold]\n")
        
        if self.confirm_action("Remove DPI iptables rules?"):
            try:
                from defense.dpi_remediation import remove_iptables_dpi
                remove_iptables_dpi()
                self.show_success("DPI rules removed")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_blue_verify_dpi(self):
        """Verify DPI"""
        self.console.print("\n[bold]Verify DPI Rules[/bold]\n")
        
        try:
            from defense.dpi_remediation import verify_dpi
            verify_dpi()
        except Exception as e:
            self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_blue_dpi_stats(self):
        """Show DPI stats"""
        self.console.print("\n[bold]DPI Statistics[/bold]\n")
        
        try:
            from defense.dpi_remediation import show_dpi_stats
            show_dpi_stats()
        except Exception as e:
            self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_blue_full(self):
        """Full blue team"""
        self.console.print("\n[bold]ULTRA Blue Team[/bold]\n")
        
        duration = self.get_int("Monitoring duration (seconds)", 30)
        
        if self.confirm_action("Run full blue team with monitoring?"):
            try:
                from defense.ultra_blue_team import run_ultra_blue_team
                run_ultra_blue_team(monitor_duration=duration)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_ids_signatures(self):
        """Generate IDS signatures"""
        self.console.print("\n[bold]IDS Signature Generation[/bold]\n")
        
        output_dir = Prompt.ask("Output directory", default="defense/signatures")
        
        if self.confirm_action("Generate Snort/Suricata/iptables signatures?"):
            try:
                from defense.ids_signatures import generate_all_signatures
                summary = generate_all_signatures(output_dir)
                self.show_success(f"Generated {summary['total_rules']} rules")
                self.console.print(f"  By Severity: {summary['by_severity']}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_honeypot(self):
        """Start honeypot network"""
        self.console.print("\n[bold]5G Honeypot Network[/bold]\n")
        
        bind_ip = self.get_ip("Bind IP address", "0.0.0.0")
        duration = self.get_int("Duration (seconds, 0=forever)", 60)
        
        self.console.print("[yellow]Starting honeypots (GTP, PFCP, SBI)...[/yellow]")
        self.console.print("[dim]Press Ctrl+C to stop[/dim]")
        
        try:
            from defense.honeypot import run_honeypot_network
            run_honeypot_network(bind_ip, duration)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Honeypots stopped[/yellow]")
        except Exception as e:
            self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_anomaly_detector(self):
        """Run anomaly detection demo"""
        self.console.print("\n[bold]Anomaly Detection[/bold]\n")
        
        if self.confirm_action("Run anomaly detection demo (5s learning + detection)?"):
            try:
                from defense.anomaly_detector import demo_anomaly_detection
                demo_anomaly_detection()
                self.show_success("Anomaly detection complete")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_security_audit(self):
        """Run security audit"""
        self.console.print("\n[bold]5G Security Audit[/bold]\n")
        
        upf = self.get_ip("UPF IP (blank to skip)", TEST_CONFIG.get("upf_ip", ""))
        amf = self.get_ip("AMF IP (blank to skip)", TEST_CONFIG.get("amf_ip", ""))
        smf = self.get_ip("SMF IP (blank to skip)", TEST_CONFIG.get("smf_ip", ""))
        nrf = self.get_ip("NRF IP (blank to skip)", "")
        
        if self.confirm_action("Run security audit?"):
            try:
                from defense.security_audit import run_security_audit
                run_security_audit(
                    upf_ip=upf if upf else None,
                    amf_ip=amf if amf else None,
                    smf_ip=smf if smf else None,
                    nrf_ip=nrf if nrf else None
                )
                self.show_success("Audit complete - see security_audit_report.json")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_menu(self):
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("4G/LTE ATTACKS", LTE_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_lte_rogue_enb()
            elif choice == "2":
                self.run_lte_initial_ue()
            elif choice == "3":
                self.run_lte_force_handover()
            elif choice == "4":
                self.run_lte_s1_reset()
            elif choice == "5":
                self.run_lte_hss_probe()
            elif choice == "6":
                self.run_lte_imsi_enum()
            elif choice == "7":
                self.run_lte_cancel_location()
            elif choice == "8":
                self.run_lte_auth_vectors()
            elif choice == "9":
                self.run_lte_full_assessment()
    
    def run_lte_rogue_enb(self):
        self.console.print("\n[bold]Rogue eNodeB Registration[/bold]\n")
        
        mme_ip = Prompt.ask("MME IP", default=TEST_CONFIG.get("mme_ip", "10.0.0.1"))
        enb_name = Prompt.ask("eNodeB Name", default="RogueENB")
        mcc = Prompt.ask("MCC", default="001")
        mnc = Prompt.ask("MNC", default="01")
        
        if Confirm.ask("Start rogue eNodeB registration?"):
            try:
                from attacks.lte_attacks import RogueENBAttack
                attack = RogueENBAttack(mme_ip)
                result = attack.register_rogue_enb(enb_name=enb_name, mcc=mcc, mnc=mnc)
                
                if result.success:
                    self.console.print("[green]eNodeB registration successful![/green]")
                else:
                    self.console.print("[yellow]Registration attempted but not confirmed[/yellow]")
                
                self.console.print(f"Details: {result.details}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_initial_ue(self):
        self.console.print("\n[bold]Initial UE Message Injection[/bold]\n")
        
        mme_ip = Prompt.ask("MME IP", default=TEST_CONFIG.get("mme_ip", "10.0.0.1"))
        mcc = Prompt.ask("MCC", default="001")
        mnc = Prompt.ask("MNC", default="01")
        
        if Confirm.ask("Inject fake Initial UE Message?"):
            try:
                from attacks.lte_attacks import RogueENBAttack
                attack = RogueENBAttack(mme_ip)
                result = attack.inject_initial_ue_message(mcc=mcc, mnc=mnc)
                
                if result.success:
                    self.console.print("[green]Initial UE message injected![/green]")
                else:
                    self.console.print("[yellow]Injection attempted[/yellow]")
                
                self.console.print(f"Details: {result.details}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_force_handover(self):
        self.console.print("\n[bold]Force UE Handover[/bold]\n")
        
        mme_ip = Prompt.ask("MME IP", default=TEST_CONFIG.get("mme_ip", "10.0.0.1"))
        mme_ue_id = IntPrompt.ask("MME UE S1AP ID", default=1)
        enb_ue_id = IntPrompt.ask("eNB UE S1AP ID", default=1)
        target_enb = Prompt.ask("Target eNodeB ID (hex)", default="0x54321")
        
        if Confirm.ask("Force handover to rogue eNodeB?"):
            try:
                from attacks.lte_attacks import RogueENBAttack
                attack = RogueENBAttack(mme_ip)
                result = attack.force_handover(
                    mme_ue_id=mme_ue_id,
                    enb_ue_id=enb_ue_id,
                    target_enb_id=int(target_enb, 16)
                )
                
                self.console.print(f"Result: {'[green]Success[/green]' if result.success else '[yellow]Attempted[/yellow]'}")
                self.console.print(f"Details: {result.details}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_s1_reset(self):
        self.console.print("\n[bold]S1 Interface Reset[/bold]\n")
        
        mme_ip = Prompt.ask("MME IP", default=TEST_CONFIG.get("mme_ip", "10.0.0.1"))
        
        self.console.print("[red]WARNING: This will reset the S1 interface![/red]")
        if Confirm.ask("Send S1 Reset?"):
            try:
                from attacks.lte_attacks import RogueENBAttack
                attack = RogueENBAttack(mme_ip)
                result = attack.s1_interface_reset()
                
                self.console.print(f"Result: {'[green]Success[/green]' if result.success else '[yellow]Attempted[/yellow]'}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_hss_probe(self):
        self.console.print("\n[bold]HSS Diameter Probe[/bold]\n")
        
        hss_ip = Prompt.ask("HSS IP", default=TEST_CONFIG.get("hss_ip", "10.0.0.2"))
        host_ip = Prompt.ask("Source IP (for CER)", default="192.168.1.100")
        
        if Confirm.ask("Probe HSS with Diameter CER?"):
            try:
                from attacks.lte_attacks import HSSAttack
                attack = HSSAttack(hss_ip)
                result = attack.diameter_cer_probe(host_ip=host_ip)
                
                if result.success:
                    self.console.print("[green]HSS responded to CER![/green]")
                    if result.details.get("peer_info"):
                        self.console.print(f"Peer Info: {result.details['peer_info']}")
                else:
                    self.console.print("[yellow]No response from HSS[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_imsi_enum(self):
        self.console.print("\n[bold]IMSI Enumeration[/bold]\n")
        
        hss_ip = Prompt.ask("HSS IP", default=TEST_CONFIG.get("hss_ip", "10.0.0.2"))
        mcc = Prompt.ask("MCC", default="001")
        mnc = Prompt.ask("MNC", default="01")
        start_msin = IntPrompt.ask("Start MSIN", default=1000000000)
        count = IntPrompt.ask("Count", default=100)
        threads = IntPrompt.ask("Threads", default=10)
        
        if Confirm.ask(f"Enumerate {count} IMSIs starting from {mcc}{mnc}{start_msin}?"):
            try:
                from attacks.lte_attacks import HSSAttack
                attack = HSSAttack(hss_ip)
                result = attack.subscriber_enumeration(
                    mcc=mcc,
                    mnc=mnc,
                    start_msin=start_msin,
                    count=count,
                    threads=threads
                )
                
                self.console.print(f"\n[bold]Found {result.details['valid_count']} valid IMSIs[/bold]")
                for imsi in result.details.get('valid_imsis', []):
                    self.console.print(f"  [green]{imsi}[/green]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_cancel_location(self):
        self.console.print("\n[bold]Cancel Location Request[/bold]\n")
        
        hss_ip = Prompt.ask("HSS IP", default=TEST_CONFIG.get("hss_ip", "10.0.0.2"))
        imsi = Prompt.ask("Target IMSI", default="001011234567890")
        
        self.console.print("[red]WARNING: This will disconnect the UE![/red]")
        if Confirm.ask("Send Cancel Location Request?"):
            try:
                from attacks.lte_attacks import HSSAttack
                attack = HSSAttack(hss_ip)
                result = attack.cancel_location(imsi=imsi)
                
                self.console.print(f"Result: {'[green]Success[/green]' if result.success else '[yellow]Attempted[/yellow]'}")
                self.console.print(f"Details: {result.details}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_auth_vectors(self):
        self.console.print("\n[bold]Authentication Vector Extraction[/bold]\n")
        
        hss_ip = Prompt.ask("HSS IP", default=TEST_CONFIG.get("hss_ip", "10.0.0.2"))
        imsi = Prompt.ask("Target IMSI", default="001011234567890")
        num_vectors = IntPrompt.ask("Number of vectors", default=5)
        
        if Confirm.ask("Extract authentication vectors?"):
            try:
                from attacks.lte_attacks import HSSAttack
                attack = HSSAttack(hss_ip)
                result = attack.extract_auth_vectors(imsi=imsi, num_vectors=num_vectors)
                
                if result.success:
                    self.console.print(f"[green]Extracted {result.details['extracted_vectors']} vectors![/green]")
                    for vec in result.details.get('vectors', []):
                        self.console.print(f"  Vector: {vec}")
                else:
                    self.console.print("[yellow]No vectors extracted[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_lte_full_assessment(self):
        self.console.print("\n[bold]Full 4G/LTE Security Assessment[/bold]\n")
        
        mme_ip = Prompt.ask("MME IP", default=TEST_CONFIG.get("mme_ip", "10.0.0.1"))
        hss_ip = Prompt.ask("HSS IP", default=TEST_CONFIG.get("hss_ip", "10.0.0.2"))
        
        if Confirm.ask("Run complete 4G/LTE assessment?"):
            try:
                from attacks.lte_attacks import run_lte_assessment
                results = run_lte_assessment(mme_ip=mme_ip, hss_ip=hss_ip)
                
                self.console.print("\n[bold]Assessment Results[/bold]")
                self.console.print(f"Total: {results['summary']['total_attacks']}")
                self.console.print(f"[green]Successful: {results['summary']['successful']}[/green]")
                self.console.print(f"[red]Failed: {results['summary']['failed']}[/red]")
                
                self.console.print("\n[bold]MME Attacks:[/bold]")
                for attack in results['mme_attacks']:
                    status = "[green]OK[/green]" if attack['success'] else "[red]FAIL[/red]"
                    self.console.print(f"  {attack['name']}: {status}")
                
                self.console.print("\n[bold]HSS Attacks:[/bold]")
                for attack in results['hss_attacks']:
                    status = "[green]OK[/green]" if attack['success'] else "[red]FAIL[/red]"
                    self.console.print(f"  {attack['name']}: {status}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_utilities_menu(self):
        """Utilities submenu"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("UTILITIES", UTILITIES_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.show_config()
            elif choice == "2":
                self.show_status()
            elif choice == "3":
                self.add_subscriber()
            elif choice == "4":
                self.list_subscribers()
            elif choice == "5":
                self.packet_capture()
            elif choice == "6":
                self.rate_limit_test()
            elif choice == "7":
                self.run_traffic_analyzer()
            elif choice == "8":
                self.run_session_tracker()
    
    def show_config(self):
        """Show configuration"""
        self.console.print("\n[bold]Current Configuration[/bold]\n")
        
        table = Table(show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in TEST_CONFIG.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
        Prompt.ask("\nPress Enter to continue")
    
    def show_status(self):
        """Show status"""
        self.console.print("\n[bold]System Status[/bold]\n")
        self.console.print(f"Running as root: {'Yes' if IS_ROOT else 'No'}")
        self.console.print(f"Rich available: {'Yes' if RICH_AVAILABLE else 'No'}")
        Prompt.ask("\nPress Enter to continue")
    
    def add_subscriber(self):
        """Add test subscriber"""
        self.console.print("\n[bold]Add Test Subscriber[/bold]\n")
        
        imsi = Prompt.ask("IMSI", default="001010000000001")
        k = Prompt.ask("K key (32 hex)", default="465B5CE8B199B49FAA5F0A2EE238A6BC")
        opc = Prompt.ask("OPc key (32 hex)", default="E8ED289DEBA952E4283B54E88E6183CA")
        
        if self.confirm_action("Add subscriber?"):
            try:
                from utils.add_subscriber import add_subscriber_mongosh
                add_subscriber_mongosh(imsi, k, opc)
                self.show_success("Subscriber added")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def list_subscribers(self):
        """List subscribers"""
        self.console.print("\n[bold]Subscribers in Database[/bold]\n")
        
        try:
            from utils.add_subscriber import list_subscribers
            list_subscribers()
        except Exception as e:
            self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def packet_capture(self):
        """Packet capture"""
        self.console.print("\n[bold]Packet Capture[/bold]\n")
        
        duration = self.get_int("Capture duration (seconds)", 30)
        
        if self.confirm_action("Start packet capture?"):
            try:
                from analysis.packet_capture import capture_gtp_traffic
                capture_gtp_traffic(duration=duration)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def rate_limit_test(self):
        """Rate limit test"""
        self.console.print("\n[bold]Rate Limit Testing[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        
        if self.confirm_action("Run rate limit detection?"):
            try:
                from analysis.rate_limit_testing import detect_rate_limiting
                detect_rate_limiting(upf_ip)
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_traffic_analyzer(self):
        """Traffic analyzer demo"""
        self.console.print("\n[bold]Traffic Analyzer[/bold]\n")
        
        if self.confirm_action("Run traffic analysis demo (simulated packets)?"):
            try:
                from analysis.traffic_analyzer import demo_traffic_analysis
                demo_traffic_analysis()
                self.show_success("Analysis exported to traffic_analysis_report.json")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_session_tracker(self):
        """Session tracker demo"""
        self.console.print("\n[bold]Session Tracker[/bold]\n")
        
        if self.confirm_action("Run session tracking demo (simulated sessions)?"):
            try:
                from analysis.session_tracker import demo_session_tracking
                demo_session_tracking()
                self.show_success("Session data exported to session_data.json")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_async_menu(self):
        """Async operations submenu"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("ASYNC OPERATIONS (5-10x FASTER)", ASYNC_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_async_scan()
            elif choice == "2":
                self.run_async_teid()
            elif choice == "3":
                self.run_async_seid()
            elif choice == "4":
                self.run_async_billing()
            elif choice == "5":
                self.run_async_dos()
            elif choice == "6":
                self.run_async_nested()
    
    def run_async_scan(self):
        """Async network scan"""
        self.console.print("\n[bold]Async Network Scan (10x faster)[/bold]\n")
        
        network = self.get_ip("Network range", "127.0.0.0/24")
        concurrency = self.get_int("Concurrency", 200)
        
        if self.confirm_action(f"Scan {network} with {concurrency} concurrent connections?"):
            try:
                import asyncio
                from discovery.async_scanner import AsyncNetworkScanner
                
                async def do_scan():
                    scanner = AsyncNetworkScanner(concurrency=concurrency)
                    return await scanner.scan_network(network)
                
                results = asyncio.run(do_scan())
                self.show_success(f"Found {len(results)} components")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_async_teid(self):
        """Async TEID enumeration"""
        self.console.print("\n[bold]Async TEID Enumeration (5x faster)[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        start = self.get_int("Start TEID", 0)
        end = self.get_int("End TEID", 10000)
        concurrency = self.get_int("Concurrency", 100)
        
        if self.confirm_action(f"Enumerate {end - start} TEIDs with {concurrency} concurrent probes?"):
            try:
                import asyncio
                from enumeration.async_enumeration import enumerate_teid_async
                
                result = asyncio.run(enumerate_teid_async(
                    upf_ip, start, end, concurrency=concurrency
                ))
                self.show_success(f"Found {len(result.get('active', []))} active TEIDs at {result.get('rate', 0):.0f}/s")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_async_seid(self):
        """Async SEID enumeration"""
        self.console.print("\n[bold]Async SEID Enumeration (5x faster)[/bold]\n")
        
        smf_ip = self.get_ip("SMF IP", TEST_CONFIG["smf_ip"])
        start = self.get_int("Start SEID", 0)
        end = self.get_int("End SEID", 10000)
        concurrency = self.get_int("Concurrency", 100)
        
        if self.confirm_action(f"Enumerate {end - start} SEIDs?"):
            try:
                import asyncio
                from enumeration.async_enumeration import enumerate_seid_async
                
                result = asyncio.run(enumerate_seid_async(
                    smf_ip, start, end, concurrency=concurrency
                ))
                self.show_success(f"Found {len(result.get('active', []))} active SEIDs")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_async_billing(self):
        """Async billing fraud"""
        self.console.print("\n[bold]Async Billing Fraud (High Throughput)[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        count = self.get_int("Packet count", 1000)
        concurrency = self.get_int("Concurrency", 50)
        
        if self.confirm_action(f"Send {count} billing fraud packets?"):
            try:
                import asyncio
                from attacks.async_attacks import AsyncBillingFraud
                
                async def do_attack():
                    attack = AsyncBillingFraud(
                        upf_ip=upf_ip,
                        outer_teid=TEST_CONFIG["outer_teid"],
                        victim_ip=TEST_CONFIG["victim_ip"],
                        victim_teid=TEST_CONFIG["victim_teid"],
                        concurrency=concurrency
                    )
                    return await attack.execute(count)
                
                result = asyncio.run(do_attack())
                self.show_success(f"Sent {result.get('packets_sent', 0)} packets at {result.get('rate', 0):.0f}/s")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_async_dos(self):
        """Async DoS attack"""
        self.console.print("\n[bold]Async DoS Attack (High Rate)[/bold]\n")
        self.console.print("[red]WARNING: High-rate denial of service[/red]\n")
        
        target_ip = self.get_ip("Target IP", TEST_CONFIG["upf_ip"])
        port = self.get_int("Target port", 2152)
        count = self.get_int("Packet count", 10000)
        
        if self.confirm_action(f"Send {count} DoS packets to {target_ip}:{port}?"):
            try:
                import asyncio
                from attacks.async_attacks import AsyncDoS
                
                async def do_dos():
                    attack = AsyncDoS(target_ip, port, concurrency=100, rate_limit=1000.0)
                    return await attack.execute(count)
                
                result = asyncio.run(do_dos())
                self.show_success(f"Sent {result.get('packets_sent', 0)} packets at {result.get('rate', 0):.0f}/s")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_async_nested(self):
        """Async nested tunnel"""
        self.console.print("\n[bold]Async Nested Tunnel Attack[/bold]\n")
        
        upf_ip = self.get_ip("UPF IP", TEST_CONFIG["upf_ip"])
        amf_ip = self.get_ip("AMF IP", TEST_CONFIG["amf_ip"])
        count = self.get_int("Packet count", 100)
        
        if self.confirm_action(f"Send {count} nested tunnel packets?"):
            try:
                import asyncio
                from attacks.async_attacks import AsyncNestedTunnel
                
                async def do_nested():
                    attack = AsyncNestedTunnel(
                        upf_ip=upf_ip,
                        outer_teid=TEST_CONFIG["outer_teid"],
                        amf_ip=amf_ip,
                        inner_teid=TEST_CONFIG["inner_teid"]
                    )
                    return await attack.execute(count)
                
                result = asyncio.run(do_nested())
                self.show_success(f"Sent {result.get('packets_sent', 0)} packets")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_protocol_menu(self):
        """Protocol tools submenu"""
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("PROTOCOL TOOLS", PROTOCOL_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_sbi_scan()
            elif choice == "2":
                self.run_sbi_discover()
            elif choice == "3":
                self.run_sbi_rogue()
            elif choice == "4":
                self.run_sctp_test()
            elif choice == "5":
                self.run_gtp_fuzz()
            elif choice == "6":
                self.run_pfcp_fuzz()
    
    def run_sbi_scan(self):
        """SBI port scanner"""
        self.console.print("\n[bold]SBI Service Scanner[/bold]\n")
        
        target = self.get_ip("Target IP", "127.0.0.1")
        
        if self.confirm_action(f"Scan {target} for SBI services?"):
            try:
                from protocol.http2_sbi import SBIScanner
                scanner = SBIScanner(target)
                results = scanner.scan_sbi_ports()
                
                if results:
                    self.console.print("\n[green]Discovered SBI Services:[/green]")
                    for svc in results:
                        self.console.print(f"  - {svc['service']} on port {svc['port']} (TLS={svc['tls']})")
                else:
                    self.console.print("[yellow]No SBI services found[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_sbi_discover(self):
        """SBI NF discovery"""
        self.console.print("\n[bold]SBI NF Instance Discovery[/bold]\n")
        
        nrf_ip = self.get_ip("NRF IP", "127.0.0.1")
        
        if self.confirm_action(f"Query NRF at {nrf_ip} for NF instances?"):
            try:
                from protocol.http2_sbi import SBIScanner
                scanner = SBIScanner(nrf_ip)
                instances = scanner.enumerate_nf_instances()
                
                if instances:
                    self.console.print("\n[green]Discovered NF Instances:[/green]")
                    for nf in instances:
                        self.console.print(f"  - {nf['nf_type']}: {nf['instances']}")
                else:
                    self.console.print("[yellow]No NF instances found (NRF may require authentication)[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_sbi_rogue(self):
        """Rogue NF registration"""
        self.console.print("\n[bold]Rogue NF Registration via SBI[/bold]\n")
        self.console.print("[red]WARNING: This attempts to register a rogue NF[/red]\n")
        
        nrf_ip = self.get_ip("NRF IP", "127.0.0.1")
        nf_type = Prompt.ask("NF Type to register", choices=["AMF", "SMF", "UPF", "UDM"], default="AMF")
        
        if self.confirm_action(f"Attempt to register rogue {nf_type}?"):
            try:
                from protocol.http2_sbi import SBIAttacks
                attacks = SBIAttacks(nrf_ip)
                result = attacks.rogue_nf_registration(nf_type=nf_type)
                
                if result:
                    self.show_success(f"Rogue {nf_type} registered!")
                else:
                    self.console.print("[yellow]Registration failed (may require authentication)[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_sctp_test(self):
        """SCTP/NGAP test"""
        self.console.print("\n[bold]SCTP/NGAP Connection Test[/bold]\n")
        
        amf_ip = self.get_ip("AMF IP", TEST_CONFIG["amf_ip"])
        port = self.get_int("SCTP Port", 38412)
        
        if self.confirm_action(f"Test SCTP connection to {amf_ip}:{port}?"):
            try:
                from protocol.sctp_enhanced import test_sctp_connection
                result = test_sctp_connection(amf_ip, port)
                
                if result.get("connected"):
                    self.show_success("SCTP association established!")
                    if result.get("ng_setup_sent"):
                        self.console.print("[green]NG Setup Request sent successfully[/green]")
                else:
                    self.console.print("[yellow]SCTP connection failed[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_gtp_fuzz(self):
        """GTP fuzzer"""
        self.console.print("\n[bold]GTP-U Protocol Fuzzer[/bold]\n")
        
        target = self.get_ip("Target UPF IP", TEST_CONFIG["upf_ip"])
        strategy = Prompt.ask("Fuzzing strategy", choices=["mutation", "boundary", "overflow"], default="mutation")
        max_cases = self.get_int("Max test cases", 100)
        
        if self.confirm_action(f"Fuzz GTP-U on {target} with {max_cases} cases?"):
            try:
                from attacks.protocol_fuzzer import GTPFuzzer, FuzzStrategy
                
                strategy_map = {
                    "mutation": FuzzStrategy.MUTATION,
                    "boundary": FuzzStrategy.BOUNDARY,
                    "overflow": FuzzStrategy.OVERFLOW
                }
                
                fuzzer = GTPFuzzer(target)
                result = fuzzer.fuzz(strategy_map[strategy], max_cases)
                
                self.console.print(f"\n[green]Fuzzing complete:[/green]")
                self.console.print(f"  Sent: {result.get('sent', 0)}")
                self.console.print(f"  Responses: {result.get('responses', 0)}")
                self.console.print(f"  Interesting: {result.get('interesting', 0)}")
                
                if result.get('interesting', 0) > 0:
                    self.console.print("\n[yellow]Interesting findings:[/yellow]")
                    for finding in result.get('interesting_results', [])[:5]:
                        self.console.print(f"  - Case {finding['case_id']}: {finding['reason']}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_pfcp_fuzz(self):
        """PFCP fuzzer"""
        self.console.print("\n[bold]PFCP Protocol Fuzzer[/bold]\n")
        
        target = self.get_ip("Target SMF IP", TEST_CONFIG["smf_ip"])
        strategy = Prompt.ask("Fuzzing strategy", choices=["mutation", "boundary", "overflow"], default="mutation")
        max_cases = self.get_int("Max test cases", 100)
        
        if self.confirm_action(f"Fuzz PFCP on {target} with {max_cases} cases?"):
            try:
                from attacks.protocol_fuzzer import PFCPFuzzer, FuzzStrategy
                
                strategy_map = {
                    "mutation": FuzzStrategy.MUTATION,
                    "boundary": FuzzStrategy.BOUNDARY,
                    "overflow": FuzzStrategy.OVERFLOW
                }
                
                fuzzer = PFCPFuzzer(target)
                result = fuzzer.fuzz(strategy_map[strategy], max_cases)
                
                self.console.print(f"\n[green]Fuzzing complete:[/green]")
                self.console.print(f"  Sent: {result.get('sent', 0)}")
                self.console.print(f"  Responses: {result.get('responses', 0)}")
                self.console.print(f"  Interesting: {result.get('interesting', 0)}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_advanced_attacks_menu(self):
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("ADVANCED ATTACKS", ADVANCED_ATTACKS_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_teid_oracle()
            elif choice == "2":
                self.run_auth_timing()
            elif choice == "3":
                self.run_rate_limit_probe()
            elif choice == "4":
                self.run_session_oracle()
            elif choice == "5":
                self.run_error_oracle()
            elif choice == "6":
                self.run_traffic_analysis()
            elif choice == "7":
                self.run_resource_exhaustion()
            elif choice == "8":
                self.run_advanced_gtp_fuzz()
            elif choice == "9":
                self.run_advanced_pfcp_fuzz()
            elif choice.upper() == "A":
                self.run_ngap_fuzz()
    
    def run_teid_oracle(self):
        self.console.print("\n[bold]TEID Oracle Timing Attack[/bold]\n")
        
        target = self.get_ip("Target UPF IP", TEST_CONFIG["upf_ip"])
        start = self.get_int("Start TEID", 0)
        end = self.get_int("End TEID", 100)
        
        if self.confirm_action(f"Run TEID oracle on {target} (TEIDs {start}-{end})?"):
            try:
                from attacks.timing_attacks import TimingAttacker
                attacker = TimingAttacker(target)
                result = attacker.teid_oracle_attack(range(start, end))
                
                self.console.print(f"\n[green]Probes: {result.total_probes}[/green]")
                self.console.print(f"Anomalies: {len(result.anomalies)}")
                
                if result.anomalies:
                    self.console.print("\n[yellow]Timing anomalies detected - possible valid TEIDs[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_auth_timing(self):
        self.console.print("\n[bold]Authentication Timing Attack[/bold]\n")
        
        target = self.get_ip("Target AMF IP", TEST_CONFIG["amf_ip"])
        
        if self.confirm_action(f"Run auth timing attack on {target}?"):
            try:
                from attacks.timing_attacks import TimingAttacker
                attacker = TimingAttacker(target, target_port=38412)
                test_imsis = [f"00101000000000{i:02d}" for i in range(10)]
                result = attacker.auth_timing_attack(test_imsis)
                
                self.console.print(f"\n[green]Probes: {result.total_probes}[/green]")
                if result.anomalies:
                    self.console.print("[yellow]Timing differences detected[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_rate_limit_probe(self):
        self.console.print("\n[bold]Rate Limit Detection[/bold]\n")
        
        target = self.get_ip("Target IP", TEST_CONFIG["upf_ip"])
        
        if self.confirm_action(f"Probe rate limits on {target}?"):
            try:
                from attacks.timing_attacks import TimingAttacker
                attacker = TimingAttacker(target)
                result = attacker.rate_limit_probe()
                
                self.console.print(f"\n[green]Probes: {result.total_probes}[/green]")
                if result.anomalies:
                    self.console.print("[yellow]Rate limiting detected[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_session_oracle(self):
        self.console.print("\n[bold]Session Oracle (PFCP Timing)[/bold]\n")
        
        target = self.get_ip("Target SMF IP", TEST_CONFIG["smf_ip"])
        start = self.get_int("Start SEID", 0)
        end = self.get_int("End SEID", 100)
        
        if self.confirm_action(f"Run session oracle on {target}?"):
            try:
                from attacks.timing_attacks import TimingAttacker
                attacker = TimingAttacker(target, target_port=8805)
                result = attacker.session_oracle_attack(range(start, end))
                
                self.console.print(f"\n[green]Probes: {result.total_probes}[/green]")
                if result.anomalies:
                    self.console.print("[yellow]Valid sessions detected via timing[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_error_oracle(self):
        self.console.print("\n[bold]Error Oracle Side-Channel[/bold]\n")
        
        target = self.get_ip("Target IP", TEST_CONFIG["upf_ip"])
        protocol = Prompt.ask("Protocol", choices=["gtp", "pfcp"], default="gtp")
        count = self.get_int("Test cases", 100)
        
        if self.confirm_action(f"Run error oracle on {target}?"):
            try:
                from attacks.side_channel import SideChannelAnalyzer, generate_malformed_gtp_inputs
                analyzer = SideChannelAnalyzer(target)
                inputs = generate_malformed_gtp_inputs(count)
                result = analyzer.error_oracle(inputs, protocol)
                
                self.console.print(f"\n[green]Patterns found: {len(result.patterns_found)}[/green]")
                if result.leakage_detected:
                    self.console.print(f"[yellow]Leakage: {result.leakage_details}[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_traffic_analysis(self):
        self.console.print("\n[bold]Traffic Pattern Analysis[/bold]\n")
        
        target = self.get_ip("Target IP", TEST_CONFIG["upf_ip"])
        duration = self.get_int("Capture duration (seconds)", 30)
        
        if self.confirm_action(f"Capture traffic for {duration}s?"):
            try:
                from attacks.side_channel import SideChannelAnalyzer
                analyzer = SideChannelAnalyzer(target)
                result = analyzer.traffic_analysis(duration=float(duration))
                
                self.console.print(f"\n[green]Packets captured: {len(result.observations)}[/green]")
                if result.leakage_detected:
                    self.console.print(f"[yellow]Pattern: {result.leakage_details}[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_resource_exhaustion(self):
        self.console.print("\n[bold]Resource Exhaustion Probe[/bold]\n")
        
        target = self.get_ip("Target IP", TEST_CONFIG["upf_ip"])
        resource = Prompt.ask("Resource type", choices=["sessions", "teids"], default="sessions")
        max_count = self.get_int("Max probes", 1000)
        
        if self.confirm_action(f"Probe {resource} limits on {target}?"):
            try:
                from attacks.side_channel import SideChannelAnalyzer
                analyzer = SideChannelAnalyzer(target)
                result = analyzer.resource_exhaustion_probe(resource, max_count)
                
                if result.leakage_detected:
                    self.console.print(f"[yellow]Exhaustion: {result.leakage_details}[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_advanced_gtp_fuzz(self):
        self.console.print("\n[bold]Advanced GTP Fuzzing[/bold]\n")
        
        target = self.get_ip("Target UPF IP", TEST_CONFIG["upf_ip"])
        max_cases = self.get_int("Max test cases", 1000)
        
        if self.confirm_action(f"Run advanced GTP fuzzing on {target}?"):
            try:
                from attacks.advanced_fuzzing import GTPFuzzer
                fuzzer = GTPFuzzer(target)
                result = fuzzer.run_campaign(max_cases)
                
                self.console.print(f"\n[green]Total: {result.total_cases}[/green]")
                self.console.print(f"Crashes: {len(result.crashes)}")
                self.console.print(f"Interesting: {len(result.interesting)}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_advanced_pfcp_fuzz(self):
        self.console.print("\n[bold]Advanced PFCP Fuzzing[/bold]\n")
        
        target = self.get_ip("Target SMF IP", TEST_CONFIG["smf_ip"])
        max_cases = self.get_int("Max test cases", 1000)
        
        if self.confirm_action(f"Run advanced PFCP fuzzing on {target}?"):
            try:
                from attacks.advanced_fuzzing import PFCPFuzzer
                fuzzer = PFCPFuzzer(target)
                result = fuzzer.run_campaign(max_cases)
                
                self.console.print(f"\n[green]Total: {result.total_cases}[/green]")
                self.console.print(f"Crashes: {len(result.crashes)}")
                self.console.print(f"Interesting: {len(result.interesting)}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_ngap_fuzz(self):
        self.console.print("\n[bold]NGAP Protocol Fuzzing[/bold]\n")
        
        target = self.get_ip("Target AMF IP", TEST_CONFIG["amf_ip"])
        max_cases = self.get_int("Max test cases", 1000)
        
        if self.confirm_action(f"Run NGAP fuzzing on {target}?"):
            try:
                from attacks.advanced_fuzzing import NGAPFuzzer
                fuzzer = NGAPFuzzer(target)
                result = fuzzer.run_campaign(max_cases)
                
                self.console.print(f"\n[green]Total: {result.total_cases}[/green]")
                self.console.print(f"Crashes: {len(result.crashes)}")
                self.console.print(f"Interesting: {len(result.interesting)}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_reporting_menu(self):
        while True:
            self.clear()
            self.show_banner()
            
            choice = self.show_menu("REPORTING & VISUALIZATION", REPORTING_MENU)
            
            if choice == "0":
                break
            elif choice == "1":
                self.run_html_report()
            elif choice == "2":
                self.run_json_report()
            elif choice == "3":
                self.run_topology_viz()
            elif choice == "4":
                self.run_session_report()
            elif choice == "5":
                self.run_start_dashboard()
            elif choice == "6":
                self.run_stop_dashboard()
    
    def run_html_report(self):
        self.console.print("\n[bold]Generate HTML Security Report[/bold]\n")
        
        title = Prompt.ask("Report title", default="5G Security Assessment")
        target_network = Prompt.ask("Target network", default="10.0.0.0/24")
        filename = Prompt.ask("Output filename", default="security_report.html")
        
        if self.confirm_action("Generate HTML report?"):
            try:
                from reporting.html_report import ReportGenerator
                gen = ReportGenerator()
                gen.set_metadata(title, "Penetration Test", target_network)
                
                path = gen.generate_html(filename)
                self.show_success(f"Report generated: {path}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_json_report(self):
        self.console.print("\n[bold]Export Results as JSON[/bold]\n")
        
        filename = Prompt.ask("Output filename", default="results.json")
        
        if self.confirm_action("Export JSON report?"):
            try:
                from reporting.html_report import ReportGenerator
                gen = ReportGenerator()
                gen.set_metadata("5G Assessment Results", "Export", "N/A")
                
                path = gen.generate_json(filename)
                self.show_success(f"JSON exported: {path}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_session_report(self):
        self.console.print("\n[bold]Generate Session Report[/bold]\n")
        self.console.print("This generates a report from all attacks, scans, and findings stored in the session database.\n")
        
        report_type = Prompt.ask("Report format", choices=["html", "json", "both"], default="html")
        
        if self.confirm_action("Generate session report?"):
            try:
                from core.results_db import ResultsDatabase
                
                db = ResultsDatabase()
                stats = db.get_statistics()
                
                self.console.print(f"\nSession Statistics:")
                self.console.print(f"  Total attacks: {stats.get('total_attacks', 0)}")
                self.console.print(f"  Total components: {stats.get('total_components', 0)}")
                self.console.print(f"  Total keys extracted: {stats.get('total_keys', 0)}\n")
                
                if report_type in ["html", "both"]:
                    html_path = db.generate_html_report()
                    self.show_success(f"HTML report: {html_path}")
                
                if report_type in ["json", "both"]:
                    json_path = db.generate_json_report()
                    self.show_success(f"JSON report: {json_path}")
                    
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_topology_viz(self):
        self.console.print("\n[bold]Network Topology Visualization[/bold]\n")
        
        filename = Prompt.ask("Output filename", default="topology.html")
        
        if self.confirm_action("Generate topology visualization?"):
            try:
                from reporting.visualization import TopologyMapper, NetworkVisualizer, NodeType, NetworkNode, NetworkLink, LinkType
                
                mapper = TopologyMapper()
                mapper.add_node(NetworkNode(id="upf1", ip=TEST_CONFIG["upf_ip"], node_type=NodeType.UPF))
                mapper.add_node(NetworkNode(id="smf1", ip=TEST_CONFIG["smf_ip"], node_type=NodeType.SMF))
                mapper.add_node(NetworkNode(id="amf1", ip=TEST_CONFIG["amf_ip"], node_type=NodeType.AMF))
                
                mapper.add_link(NetworkLink(source="amf1", target="smf1", link_type=LinkType.SBI))
                mapper.add_link(NetworkLink(source="smf1", target="upf1", link_type=LinkType.PFCP))
                
                viz = NetworkVisualizer()
                path = viz.generate_html(mapper, filename)
                self.show_success(f"Topology visualization: {path}")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_start_dashboard(self):
        self.console.print("\n[bold]Start Real-Time Dashboard[/bold]\n")
        
        port = self.get_int("Dashboard port", 8080)
        
        if self.confirm_action(f"Start dashboard on port {port}?"):
            try:
                from reporting.dashboard import DashboardServer
                
                if not hasattr(self, '_dashboard_server') or self._dashboard_server is None:
                    self._dashboard_server = DashboardServer(port=port)
                    self._dashboard_server.start(blocking=False)
                    self.show_success(f"Dashboard running at http://localhost:{port}")
                else:
                    self.console.print("[yellow]Dashboard already running[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")
    
    def run_stop_dashboard(self):
        self.console.print("\n[bold]Stop Dashboard[/bold]\n")
        
        if self.confirm_action("Stop the dashboard server?"):
            try:
                if hasattr(self, '_dashboard_server') and self._dashboard_server is not None:
                    self._dashboard_server.stop()
                    self._dashboard_server = None
                    self.show_success("Dashboard stopped")
                else:
                    self.console.print("[yellow]No dashboard running[/yellow]")
            except Exception as e:
                self.show_error(str(e))
        
        Prompt.ask("\nPress Enter to continue")


# ============================================================================
# DIRECT COMMAND MODE (argparse)
# ============================================================================

def setup_argparse():
    """Setup argument parser for direct command mode"""
    parser = argparse.ArgumentParser(
        description='5G-Gibbon: 5G Security Testing Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DIRECT COMMANDS:
  python run.py discover              Discover network components
  python run.py audit                 Run security audit
  python run.py ultra-red             Run full red team
  python run.py ultra-blue            Run full blue team
  
KEY EXTRACTION:
  python run.py keys standard         Standard extraction
  python run.py keys nuclear          Nuclear extraction

BASIC ATTACKS:
  python run.py attack billing        Billing fraud
  python run.py attack nested         Nested tunnels
  python run.py attack teid           TEID enumeration

ASYNC (5-10x FASTER):
  python run.py async scan            Async network scan
  python run.py async teid            Async TEID enumeration
  python run.py async billing         Async billing fraud
  python run.py async dos             Async DoS attack

ADVANCED ATTACKS:
  python run.py timing teid-oracle    TEID oracle timing attack
  python run.py timing rate-probe     Rate limit detection
  python run.py sidechan error-oracle Error-based side-channel
  python run.py sidechan traffic      Traffic pattern analysis
  python run.py fuzz gtp              Advanced GTP fuzzing
  python run.py fuzz pfcp             Advanced PFCP fuzzing
  python run.py fuzz ngap             NGAP protocol fuzzing

PROTOCOL TOOLS:
  python run.py protocol sbi-scan     Scan for SBI services
  python run.py protocol sbi-discover Discover NF instances
  python run.py protocol sctp-test    Test SCTP/NGAP connection
  python run.py protocol fuzz-gtp     Fuzz GTP-U protocol

REPORTING:
  python run.py report html           Generate HTML report
  python run.py report json           Export as JSON
  python run.py report topology       Network topology visualization
  python run.py dashboard             Start real-time dashboard

DEFENSE:
  python run.py dpi apply             Apply DPI rules
  python run.py dpi remove            Remove DPI rules

4G/LTE ATTACKS:
  python run.py lte rogue-enb         Register rogue eNodeB
  python run.py lte hss-probe         Probe HSS via Diameter
  python run.py lte imsi-enum         Enumerate IMSIs
  python run.py lte auth-vectors      Extract auth vectors
  python run.py lte assessment        Full 4G/LTE assessment

INTERACTIVE MODE:
  python run.py                       Launch interactive menu
"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Discovery
    discover_parser = subparsers.add_parser('discover', help='Discover 5G network components')
    discover_parser.add_argument('--network', default='127.0.0.0/24', help='Network range')
    
    # Audit
    audit_parser = subparsers.add_parser('audit', help='Run security audit')
    audit_parser.add_argument('--client', default='Test Client', help='Client name')
    
    # Keys
    keys_parser = subparsers.add_parser('keys', help='Key extraction')
    keys_parser.add_argument('level', choices=['standard', 'stress', 'nuclear', 'maximum'], help='Extraction level')
    
    # Attack
    attack_parser = subparsers.add_parser('attack', help='Run specific attack')
    attack_parser.add_argument('type', choices=['billing', 'nested', 'teid', 'pfcp', 'ue', 'rogue', 'ngap'], help='Attack type')
    attack_parser.add_argument('--target', help='Target IP')
    attack_parser.add_argument('--count', type=int, default=10, help='Packet count')
    
    # DPI
    dpi_parser = subparsers.add_parser('dpi', help='DPI management')
    dpi_parser.add_argument('action', choices=['apply', 'remove', 'verify', 'stats'], help='DPI action')
    
    # Ultra Red
    red_parser = subparsers.add_parser('ultra-red', help='Full red team attack')
    red_parser.add_argument('--intensity', choices=['standard', 'maximum'], default='maximum')
    
    # Ultra Blue
    blue_parser = subparsers.add_parser('ultra-blue', help='Full blue team defense')
    blue_parser.add_argument('--duration', type=int, default=30, help='Monitoring duration')
    blue_parser.add_argument('--deploy-only', action='store_true', help='Deploy only, no monitoring')
    
    # Async operations
    async_parser = subparsers.add_parser('async', help='Async operations (5-10x faster)')
    async_parser.add_argument('operation', choices=['scan', 'teid', 'seid', 'billing', 'dos', 'nested'], help='Async operation')
    async_parser.add_argument('--target', help='Target IP')
    async_parser.add_argument('--network', default='127.0.0.0/24', help='Network for scan')
    async_parser.add_argument('--start', type=int, default=0, help='Start TEID/SEID')
    async_parser.add_argument('--end', type=int, default=10000, help='End TEID/SEID')
    async_parser.add_argument('--count', type=int, default=1000, help='Packet count')
    async_parser.add_argument('--concurrency', '-c', type=int, default=100, help='Concurrency level')
    async_parser.add_argument('--rate', '-r', type=float, default=500.0, help='Rate limit')
    
    # Protocol tools
    protocol_parser = subparsers.add_parser('protocol', help='Protocol tools (SBI, SCTP, Fuzzing)')
    protocol_parser.add_argument('tool', choices=['sbi-scan', 'sbi-discover', 'sbi-rogue', 'sctp-test', 'fuzz-gtp', 'fuzz-pfcp'], help='Protocol tool')
    protocol_parser.add_argument('--target', help='Target IP')
    protocol_parser.add_argument('--port', type=int, help='Target port')
    protocol_parser.add_argument('--nf-type', choices=['AMF', 'SMF', 'UPF', 'UDM'], default='AMF', help='NF type for rogue registration')
    protocol_parser.add_argument('--strategy', choices=['mutation', 'boundary', 'overflow'], default='mutation', help='Fuzzing strategy')
    protocol_parser.add_argument('--max-cases', type=int, default=100, help='Max fuzz cases')
    
    timing_parser = subparsers.add_parser('timing', help='Timing attacks (TEID oracle, rate limit detection)')
    timing_parser.add_argument('attack', choices=['teid-oracle', 'auth-timing', 'rate-probe', 'session-oracle'], help='Timing attack type')
    timing_parser.add_argument('--target', help='Target IP')
    timing_parser.add_argument('--start', type=int, default=0, help='Start TEID/SEID')
    timing_parser.add_argument('--end', type=int, default=100, help='End TEID/SEID')
    timing_parser.add_argument('--samples', type=int, default=5, help='Samples per probe')
    
    sidechan_parser = subparsers.add_parser('sidechan', help='Side-channel analysis')
    sidechan_parser.add_argument('analysis', choices=['error-oracle', 'traffic', 'exhaustion', 'size-oracle'], help='Analysis type')
    sidechan_parser.add_argument('--target', help='Target IP')
    sidechan_parser.add_argument('--duration', type=float, default=30.0, help='Capture duration')
    sidechan_parser.add_argument('--count', type=int, default=100, help='Test cases')
    
    fuzz_parser = subparsers.add_parser('fuzz', help='Advanced protocol fuzzing')
    fuzz_parser.add_argument('protocol', choices=['gtp', 'pfcp', 'ngap'], help='Protocol to fuzz')
    fuzz_parser.add_argument('--target', help='Target IP')
    fuzz_parser.add_argument('--cases', type=int, default=1000, help='Max test cases')
    
    report_parser = subparsers.add_parser('report', help='Generate reports and visualizations')
    report_parser.add_argument('type', choices=['html', 'json', 'topology'], help='Report type')
    report_parser.add_argument('--title', default='5G Security Assessment', help='Report title')
    report_parser.add_argument('--output', '-o', default='report.html', help='Output filename')
    report_parser.add_argument('--network', default='10.0.0.0/24', help='Target network for report')
    
    dashboard_parser = subparsers.add_parser('dashboard', help='Start real-time dashboard')
    dashboard_parser.add_argument('--port', '-p', type=int, default=8080, help='Dashboard port')
    dashboard_parser.add_argument('--demo', action='store_true', help='Run with demo data')
    
    lte_parser = subparsers.add_parser('lte', help='4G/LTE attacks (S1AP, Diameter)')
    lte_parser.add_argument('type', choices=['rogue-enb', 'initial-ue', 'handover', 's1-reset', 'hss-probe', 'imsi-enum', 'cancel-location', 'auth-vectors', 'assessment'], help='LTE attack type')
    lte_parser.add_argument('--mme', help='MME IP address')
    lte_parser.add_argument('--hss', help='HSS IP address')
    lte_parser.add_argument('--imsi', help='Target IMSI')
    lte_parser.add_argument('--mcc', default='001', help='Mobile Country Code')
    lte_parser.add_argument('--mnc', default='01', help='Mobile Network Code')
    lte_parser.add_argument('--count', type=int, default=100, help='Number of IMSIs to enumerate')
    lte_parser.add_argument('--threads', type=int, default=10, help='Thread count for enumeration')
    
    defense_parser = subparsers.add_parser('defense', help='Blue team defense modules')
    defense_parser.add_argument('type', choices=['ids', 'honeypot', 'anomaly', 'audit'], help='Defense module type')
    defense_parser.add_argument('--output', help='Output file for IDS rules')
    defense_parser.add_argument('--duration', type=int, default=300, help='Duration in seconds')
    defense_parser.add_argument('--interface', help='Network interface for monitoring')
    
    analysis_parser = subparsers.add_parser('analysis', help='Traffic analysis modules')
    analysis_parser.add_argument('type', choices=['traffic', 'session', 'pcap'], help='Analysis module type')
    analysis_parser.add_argument('--pcap', help='PCAP file to analyze')
    analysis_parser.add_argument('--interface', help='Network interface for live capture')
    analysis_parser.add_argument('--duration', type=int, default=60, help='Capture duration in seconds')
    
    return parser


def run_direct_mode(args):
    """Execute direct command mode"""
    if args.command == 'discover':
        from discovery.network_discovery import discover_5g_network, display_discovered_network
        components, all_hosts = discover_5g_network(args.network)
        display_discovered_network(components, all_hosts)
        
    elif args.command == 'audit':
        from audit.security_audit import run_full_audit
        run_full_audit(client_name=args.client)
        
    elif args.command == 'keys':
        if args.level == 'standard':
            from key_extraction.ngap_key_extraction import rogue_gnodeb_with_key_extraction
            rogue_gnodeb_with_key_extraction(
                upf_ip=TEST_CONFIG["upf_ip"],
                outer_teid=TEST_CONFIG["outer_teid"],
                amf_ip=TEST_CONFIG["amf_ip"],
                inner_teid=TEST_CONFIG["inner_teid"]
            )
        elif args.level == 'stress':
            from key_extraction.key_extraction_stress import run_full_stress_test
            run_full_stress_test()
        elif args.level == 'nuclear':
            from key_extraction.nuclear_key_extraction import NuclearKeyExtraction
            nuke = NuclearKeyExtraction()
            nuke.run_nuclear_extraction()
        elif args.level == 'maximum':
            from key_extraction.maximum_extraction import run_maximum
            run_maximum()
            
    elif args.command == 'attack':
        target = args.target or TEST_CONFIG["upf_ip"]
        if args.type == 'billing':
            from attacks.billing_fraud import reflective_injection
            reflective_injection(
                upf_ip=target,
                outer_teid=TEST_CONFIG["outer_teid"],
                victim_ip=TEST_CONFIG["victim_ip"],
                victim_teid=TEST_CONFIG["victim_teid"],
                count=args.count
            )
        elif args.type == 'nested':
            from attacks.nested_tunnel_testing import test_nested_depth
            test_nested_depth(target)
        elif args.type == 'teid':
            from enumeration.teid_seid_enumeration import enumerate_teid
            enumerate_teid(target, 0, 1000)
        elif args.type == 'pfcp':
            from attacks.pfcp_attacks import pfcp_association_attack
            pfcp_association_attack(TEST_CONFIG["smf_ip"])
        elif args.type == 'ue':
            from attacks.ue_to_ue_injection import battery_drain_attack
            battery_drain_attack(
                upf_ip=target,
                attacker_ue_ip=TEST_CONFIG["attacker_ue_ip"],
                attacker_teid=TEST_CONFIG["outer_teid"],
                victim_ue_ip=TEST_CONFIG["victim_ip"],
                victim_teid=TEST_CONFIG["victim_teid"]
            )
        elif args.type == 'rogue':
            from attacks.rogue_gnodeb import rogue_gnodeb_register
            rogue_gnodeb_register(
                upf_ip=target,
                outer_teid=TEST_CONFIG["outer_teid"],
                amf_ip=TEST_CONFIG["amf_ip"],
                inner_teid=TEST_CONFIG["inner_teid"]
            )
        elif args.type == 'ngap':
            from attacks.ngap_injection import inject_ngap
            inject_ngap(
                upf_ip=target,
                outer_teid=TEST_CONFIG["outer_teid"],
                amf_ip=TEST_CONFIG["amf_ip"],
                inner_teid=TEST_CONFIG["inner_teid"]
            )
        
        elif args.command == 'dpi':
            if args.action == 'apply':
                from defense.dpi_remediation import apply_iptables_dpi
                apply_iptables_dpi()
            elif args.action == 'remove':
                from defense.dpi_remediation import remove_iptables_dpi
                remove_iptables_dpi()
            elif args.action == 'verify':
                from defense.dpi_remediation import verify_dpi
                verify_dpi()
            elif args.action == 'stats':
                from defense.dpi_remediation import show_dpi_stats
                show_dpi_stats()
        
        elif args.command == 'ultra-red':
            from red_team.ultra_red_team import run_ultra_red_team
            run_ultra_red_team(intensity=args.intensity)
        
        elif args.command == 'ultra-blue':
            if args.deploy_only:
                from defense.ultra_blue_team import deploy_defenses_only
                deploy_defenses_only()
            else:
                from defense.ultra_blue_team import run_ultra_blue_team
                run_ultra_blue_team(monitor_duration=args.duration)
    
    elif args.command == 'async':
        import asyncio
        target = args.target or TEST_CONFIG["upf_ip"]
        
        if args.operation == 'scan':
            from discovery.async_scanner import AsyncNetworkScanner
            async def do_scan():
                scanner = AsyncNetworkScanner(concurrency=args.concurrency)
                return await scanner.scan_network(args.network)
            results = asyncio.run(do_scan())
            print(f"Found {len(results)} components")
            
        elif args.operation == 'teid':
            from enumeration.async_enumeration import enumerate_teid_async
            result = asyncio.run(enumerate_teid_async(
                target, args.start, args.end,
                concurrency=args.concurrency, rate_limit=args.rate
            ))
            print(f"Found {len(result.get('active', []))} active TEIDs at {result.get('rate', 0):.0f}/s")
            
        elif args.operation == 'seid':
            from enumeration.async_enumeration import enumerate_seid_async
            smf = args.target or TEST_CONFIG["smf_ip"]
            result = asyncio.run(enumerate_seid_async(
                smf, args.start, args.end,
                concurrency=args.concurrency, rate_limit=args.rate
            ))
            print(f"Found {len(result.get('active', []))} active SEIDs")
            
        elif args.operation == 'billing':
            from attacks.async_attacks import AsyncBillingFraud
            async def do_billing():
                attack = AsyncBillingFraud(
                    upf_ip=target,
                    outer_teid=TEST_CONFIG["outer_teid"],
                    victim_ip=TEST_CONFIG["victim_ip"],
                    victim_teid=TEST_CONFIG["victim_teid"],
                    concurrency=args.concurrency
                )
                return await attack.execute(args.count)
            result = asyncio.run(do_billing())
            print(f"Sent {result.get('packets_sent', 0)} at {result.get('rate', 0):.0f}/s")
            
        elif args.operation == 'dos':
            from attacks.async_attacks import AsyncDoS
            async def do_dos():
                attack = AsyncDoS(target, 2152, concurrency=args.concurrency)
                return await attack.execute(args.count)
            result = asyncio.run(do_dos())
            print(f"Sent {result.get('packets_sent', 0)} at {result.get('rate', 0):.0f}/s")
            
        elif args.operation == 'nested':
            from attacks.async_attacks import AsyncNestedTunnel
            async def do_nested():
                attack = AsyncNestedTunnel(
                    upf_ip=target,
                    outer_teid=TEST_CONFIG["outer_teid"],
                    amf_ip=TEST_CONFIG["amf_ip"],
                    inner_teid=TEST_CONFIG["inner_teid"]
                )
                return await attack.execute(args.count)
            result = asyncio.run(do_nested())
            print(f"Sent {result.get('packets_sent', 0)} packets")
    
    elif args.command == 'protocol':
        target = args.target or "127.0.0.1"
        
        if args.tool == 'sbi-scan':
            from protocol.http2_sbi import SBIScanner
            scanner = SBIScanner(target)
            results = scanner.scan_sbi_ports()
            for svc in results:
                print(f"Found {svc['service']} on port {svc['port']}")
                
        elif args.tool == 'sbi-discover':
            from protocol.http2_sbi import SBIScanner
            scanner = SBIScanner(target)
            instances = scanner.enumerate_nf_instances()
            for nf in instances:
                print(f"{nf['nf_type']}: {nf['instances']}")
                
        elif args.tool == 'sbi-rogue':
            from protocol.http2_sbi import SBIAttacks
            attacks = SBIAttacks(target)
            result = attacks.rogue_nf_registration(nf_type=args.nf_type)
            print(f"Registration result: {result}")
            
        elif args.tool == 'sctp-test':
            from protocol.sctp_enhanced import test_sctp_connection
            port = args.port or 38412
            result = test_sctp_connection(target, port)
            print(f"SCTP test result: {result}")
            
        elif args.tool == 'fuzz-gtp':
            from attacks.protocol_fuzzer import GTPFuzzer, FuzzStrategy
            strategy_map = {"mutation": FuzzStrategy.MUTATION, "boundary": FuzzStrategy.BOUNDARY, "overflow": FuzzStrategy.OVERFLOW}
            fuzzer = GTPFuzzer(target)
            result = fuzzer.fuzz(strategy_map[args.strategy], args.max_cases)
            print(f"Fuzzing: {result.get('sent', 0)} sent, {result.get('interesting', 0)} interesting")
            
        elif args.tool == 'fuzz-pfcp':
            from attacks.protocol_fuzzer import PFCPFuzzer, FuzzStrategy
            strategy_map = {"mutation": FuzzStrategy.MUTATION, "boundary": FuzzStrategy.BOUNDARY, "overflow": FuzzStrategy.OVERFLOW}
            fuzzer = PFCPFuzzer(target)
            result = fuzzer.fuzz(strategy_map[args.strategy], args.max_cases)
            print(f"Fuzzing: {result.get('sent', 0)} sent, {result.get('interesting', 0)} interesting")
    
    elif args.command == 'timing':
        target = args.target or TEST_CONFIG["upf_ip"]
        from attacks.timing_attacks import TimingAttacker
        attacker = TimingAttacker(target, samples_per_probe=args.samples)
        
        if args.attack == 'teid-oracle':
            result = attacker.teid_oracle_attack(range(args.start, args.end))
            print(f"Probes: {result.total_probes}, Anomalies: {len(result.anomalies)}")
        elif args.attack == 'auth-timing':
            test_imsis = [f"00101000000000{i:02d}" for i in range(10)]
            result = attacker.auth_timing_attack(test_imsis)
            print(f"Probes: {result.total_probes}, Anomalies: {len(result.anomalies)}")
        elif args.attack == 'rate-probe':
            result = attacker.rate_limit_probe()
            print(f"Probes: {result.total_probes}, Anomalies: {len(result.anomalies)}")
        elif args.attack == 'session-oracle':
            smf = args.target or TEST_CONFIG["smf_ip"]
            attacker = TimingAttacker(smf, target_port=8805, samples_per_probe=args.samples)
            result = attacker.session_oracle_attack(range(args.start, args.end))
            print(f"Probes: {result.total_probes}, Anomalies: {len(result.anomalies)}")
    
    elif args.command == 'sidechan':
        target = args.target or TEST_CONFIG["upf_ip"]
        from attacks.side_channel import SideChannelAnalyzer, generate_malformed_gtp_inputs
        analyzer = SideChannelAnalyzer(target)
        
        if args.analysis == 'error-oracle':
            inputs = generate_malformed_gtp_inputs(args.count)
            result = analyzer.error_oracle(inputs, "gtp")
            print(f"Patterns: {len(result.patterns_found)}, Leakage: {result.leakage_detected}")
        elif args.analysis == 'traffic':
            result = analyzer.traffic_analysis(duration=args.duration)
            print(f"Packets: {len(result.observations)}, Pattern detected: {result.leakage_detected}")
        elif args.analysis == 'exhaustion':
            result = analyzer.resource_exhaustion_probe(max_count=args.count)
            print(f"Exhaustion detected: {result.leakage_detected}")
    
    elif args.command == 'fuzz':
        target = args.target or TEST_CONFIG["upf_ip"]
        
        if args.protocol == 'gtp':
            from attacks.advanced_fuzzing import GTPFuzzer
            fuzzer = GTPFuzzer(target)
            result = fuzzer.run_campaign(args.cases)
            print(f"Total: {result.total_cases}, Crashes: {len(result.crashes)}, Interesting: {len(result.interesting)}")
        elif args.protocol == 'pfcp':
            target = args.target or TEST_CONFIG["smf_ip"]
            from attacks.advanced_fuzzing import PFCPFuzzer
            fuzzer = PFCPFuzzer(target)
            result = fuzzer.run_campaign(args.cases)
            print(f"Total: {result.total_cases}, Crashes: {len(result.crashes)}, Interesting: {len(result.interesting)}")
        elif args.protocol == 'ngap':
            target = args.target or TEST_CONFIG["amf_ip"]
            from attacks.advanced_fuzzing import NGAPFuzzer
            fuzzer = NGAPFuzzer(target)
            result = fuzzer.run_campaign(args.cases)
            print(f"Total: {result.total_cases}, Crashes: {len(result.crashes)}, Interesting: {len(result.interesting)}")
    
    elif args.command == 'report':
        from reporting.html_report import ReportGenerator
        gen = ReportGenerator()
        gen.set_metadata(args.title, "Security Assessment", args.network)
        
        if args.type == 'html':
            path = gen.generate_html(args.output)
            print(f"HTML report generated: {path}")
        elif args.type == 'json':
            output = args.output.replace('.html', '.json') if args.output.endswith('.html') else args.output
            path = gen.generate_json(output)
            print(f"JSON report generated: {path}")
        elif args.type == 'topology':
            from reporting.visualization import TopologyMapper, NetworkVisualizer, NodeType, NetworkNode, NetworkLink, LinkType
            mapper = TopologyMapper()
            mapper.add_node(NetworkNode(id="upf1", ip=TEST_CONFIG["upf_ip"], node_type=NodeType.UPF))
            mapper.add_node(NetworkNode(id="smf1", ip=TEST_CONFIG["smf_ip"], node_type=NodeType.SMF))
            mapper.add_node(NetworkNode(id="amf1", ip=TEST_CONFIG["amf_ip"], node_type=NodeType.AMF))
            mapper.add_link(NetworkLink(source="amf1", target="smf1", link_type=LinkType.SBI))
            mapper.add_link(NetworkLink(source="smf1", target="upf1", link_type=LinkType.PFCP))
            viz = NetworkVisualizer()
            output = args.output.replace('.html', '_topology.html') if args.output.endswith('.html') else args.output
            path = viz.generate_html(mapper, output)
            print(f"Topology visualization: {path}")
    
    elif args.command == 'dashboard':
        from reporting.dashboard import DashboardServer
        server = DashboardServer(port=args.port)
        print(f"Starting dashboard on http://localhost:{args.port}")
        server.start(blocking=True)
    
    elif args.command == 'lte':
        mme_ip = args.mme or TEST_CONFIG.get("mme_ip", "10.0.0.1")
        hss_ip = args.hss or TEST_CONFIG.get("hss_ip", "10.0.0.2")
        
        if args.type == 'rogue-enb':
            from attacks.lte_attacks import RogueENBAttack
            attack = RogueENBAttack(mme_ip)
            result = attack.register_rogue_enb(mcc=args.mcc, mnc=args.mnc)
            print(f"Rogue eNodeB Registration: {'Success' if result.success else 'Failed'}")
            print(f"Details: {result.details}")
            
        elif args.type == 'initial-ue':
            from attacks.lte_attacks import RogueENBAttack
            attack = RogueENBAttack(mme_ip)
            result = attack.inject_initial_ue_message(mcc=args.mcc, mnc=args.mnc)
            print(f"Initial UE Injection: {'Success' if result.success else 'Attempted'}")
            
        elif args.type == 'handover':
            from attacks.lte_attacks import RogueENBAttack
            attack = RogueENBAttack(mme_ip)
            result = attack.force_handover(mme_ue_id=1, enb_ue_id=1)
            print(f"Force Handover: {'Success' if result.success else 'Attempted'}")
            
        elif args.type == 's1-reset':
            from attacks.lte_attacks import RogueENBAttack
            attack = RogueENBAttack(mme_ip)
            result = attack.s1_interface_reset()
            print(f"S1 Reset: {'Success' if result.success else 'Attempted'}")
            
        elif args.type == 'hss-probe':
            from attacks.lte_attacks import HSSAttack
            attack = HSSAttack(hss_ip)
            result = attack.diameter_cer_probe()
            print(f"HSS Probe: {'Connected' if result.success else 'No response'}")
            if result.details.get('peer_info'):
                print(f"Peer Info: {result.details['peer_info']}")
            
        elif args.type == 'imsi-enum':
            from attacks.lte_attacks import HSSAttack
            attack = HSSAttack(hss_ip)
            result = attack.subscriber_enumeration(
                mcc=args.mcc,
                mnc=args.mnc,
                count=args.count,
                threads=args.threads
            )
            print(f"Found {result.details['valid_count']} valid IMSIs")
            for imsi in result.details.get('valid_imsis', []):
                print(f"  {imsi}")
            
        elif args.type == 'cancel-location':
            if not args.imsi:
                print("Error: --imsi required for cancel-location")
                return
            from attacks.lte_attacks import HSSAttack
            attack = HSSAttack(hss_ip)
            result = attack.cancel_location(imsi=args.imsi)
            print(f"Cancel Location: {'Success' if result.success else 'Failed'}")
            
        elif args.type == 'auth-vectors':
            if not args.imsi:
                print("Error: --imsi required for auth-vectors")
                return
            from attacks.lte_attacks import HSSAttack
            attack = HSSAttack(hss_ip)
            result = attack.extract_auth_vectors(imsi=args.imsi)
            print(f"Extracted {result.details.get('extracted_vectors', 0)} vectors")
            
        elif args.type == 'assessment':
            from attacks.lte_attacks import run_lte_assessment
            results = run_lte_assessment(mme_ip=mme_ip, hss_ip=hss_ip)
            print(f"\nTotal: {results['summary']['total_attacks']}")
            print(f"Successful: {results['summary']['successful']}")
            print(f"Failed: {results['summary']['failed']}")

    elif args.command == 'defense':
        if args.type == 'ids':
            from defense.ids_signatures import IDSSignatureGenerator
            gen = IDSSignatureGenerator()
            rules = gen.generate_5g_attack_signatures()
            output = args.output or "ids_rules.txt"
            with open(output, 'w') as f:
                for rule in rules:
                    f.write(f"SID {rule.sid}: {rule.name} - {rule.description}\n")
            print(f"IDS rules written to {output} ({len(rules)} rules)")
            
        elif args.type == 'honeypot':
            from defense.honeypot import Honeypot5GOrchestrator
            orchestrator = Honeypot5GOrchestrator()
            orchestrator.add_all()
            print(f"Starting honeypot network for {args.duration}s...")
            orchestrator.start_all()
            import time
            try:
                time.sleep(args.duration)
            except KeyboardInterrupt:
                pass
            orchestrator.stop_all()
            stats = orchestrator.get_statistics()
            print(f"Total events: {stats['total_attacks']}")
            
        elif args.type == 'anomaly':
            from defense.anomaly_detector import Anomaly5GDetector
            detector = Anomaly5GDetector()
            print(f"Anomaly detector initialized (sensitivity: {detector.sensitivity}). Use interactive mode for real-time monitoring.")
            
        elif args.type == 'audit':
            from defense.security_audit import Security5GAuditor
            auditor = Security5GAuditor()
            report = auditor.run_full_audit()
            print(f"Audit complete: {report.total_checks} checks, {report.failed} issues found")
    
    elif args.command == 'analysis':
        if args.type == 'traffic':
            from analysis.traffic_analyzer import Traffic5GAnalyzer
            analyzer = Traffic5GAnalyzer()
            print(f"Traffic analyzer initialized. Ready to analyze packets (flows: {len(analyzer.flows)}).")
            
        elif args.type == 'session':
            from analysis.session_tracker import Session5GTracker
            tracker = Session5GTracker()
            print(f"Session tracker initialized. Tracking {len(tracker.ue_sessions)} UE sessions.")
            
        elif args.type == 'pcap':
            from analysis.pcap_analyzer import PcapAnalyzer
            if not args.pcap:
                print("Error: --pcap required")
                return
            analyzer = PcapAnalyzer(args.pcap)
            if analyzer.load_pcap():
                analyzer.run_full_analysis()
                analyzer.print_summary()
            else:
                print("Failed to load PCAP file")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point - decides between interactive and direct mode"""
    
    # If no arguments, launch interactive mode
    if len(sys.argv) == 1:
        if RICH_AVAILABLE:
            interactive = InteractiveMode()
            interactive.run()
        else:
            print("Interactive mode requires Rich library.")
            print("Install with: pip install rich")
            print("\nOr use direct command mode: python cli.py --help")
            return 1
    else:
        # Direct command mode
        parser = setup_argparse()
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return 1
        
        try:
            run_direct_mode(args)
        except Exception as e:
            logger.error(f"Error: {e}")
            return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
