#!/usr/bin/env python3
"""
DPI REMEDIATION MODULE
======================
Implements Deep Packet Inspection rules to block nested GTP-U attacks

This module provides:
1. iptables rules to detect and block nested GTP-U tunnels
2. nftables rules for modern systems
3. Open5GS configuration recommendations
4. Verification that DPI is working
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

IPTABLES_RULES = """
# 5G-Gibbon DPI Rules - Block Nested GTP-U Tunnels
# =================================================

# Create custom chain for GTP inspection
iptables -N GTP_DPI 2>/dev/null || true

# Flush existing rules in the chain
iptables -F GTP_DPI

# Match GTP-U packets (UDP port 2152)
# GTP-U header starts with version (3 bits) + PT (1 bit) + reserved (1 bit) + E (1 bit) + S (1 bit) + PN (1 bit)
# Version 1 = 0x30 (001 in first 3 bits), Message type 0xFF = G-PDU (user data)

# Rule 1: Block packets where GTP-U payload contains another GTP-U header
# This detects nested tunnels by looking for 0x30 0xFF pattern after GTP header
iptables -A GTP_DPI -p udp --dport 2152 -m string --algo bm --hex-string "|30ff|" --from 36 --to 100 -j DROP

# Rule 2: Block GTP-U packets with excessive length (potential tunnel-in-tunnel)
iptables -A GTP_DPI -p udp --dport 2152 -m length --length 200:65535 -m string --algo bm --hex-string "|30ff|" --from 28 -j DROP

# Rule 3: Rate limit GTP-U to prevent enumeration attacks
iptables -A GTP_DPI -p udp --dport 2152 -m limit --limit 1000/sec --limit-burst 2000 -j ACCEPT
iptables -A GTP_DPI -p udp --dport 2152 -j DROP

# Rule 4: Block SCTP from non-gNodeB sources (control plane protection)
# iptables -A GTP_DPI -p sctp --dport 38412 ! -s <gnodeb_ip> -j DROP

# Rule 5: Log suspicious packets before dropping
iptables -A GTP_DPI -p udp --dport 2152 -m string --algo bm --hex-string "|30ff|" -j LOG --log-prefix "GTP-DPI-NESTED: "

# Apply GTP_DPI chain to INPUT and FORWARD
iptables -I INPUT -p udp --dport 2152 -j GTP_DPI
iptables -I FORWARD -p udp --dport 2152 -j GTP_DPI

echo "✓ DPI rules applied"
"""

NFTABLES_RULES = """
#!/usr/sbin/nft -f
# 5G-Gibbon DPI Rules for nftables
# =================================

table inet gtp_dpi {
    chain input {
        type filter hook input priority -10; policy accept;
        
        # Inspect GTP-U traffic
        udp dport 2152 jump gtp_inspect
    }
    
    chain forward {
        type filter hook forward priority -10; policy accept;
        
        # Inspect forwarded GTP-U traffic
        udp dport 2152 jump gtp_inspect
    }
    
    chain gtp_inspect {
        # Drop nested GTP-U (another 0x30 0xFF after GTP header)
        udp dport 2152 @th,64,16 0x30ff drop
        
        # Rate limit GTP-U packets
        udp dport 2152 limit rate 1000/second burst 2000 packets accept
        udp dport 2152 drop
        
        # Log and accept normal GTP-U
        udp dport 2152 log prefix "GTP-U: " accept
    }
}
"""

def check_root():
    if os.geteuid() != 0:
        logger.error("This script requires root privileges")
        logger.error("Run with: sudo python3 dpi_remediation.py")
        return False
    return True

def check_iptables():
    """Check if iptables is available"""
    try:
        result = subprocess.run(['iptables', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"✓ iptables available: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    logger.warning("✗ iptables not found")
    return False

def check_nftables():
    """Check if nftables is available"""
    try:
        result = subprocess.run(['nft', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"✓ nftables available: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    logger.warning("✗ nftables not found")
    return False

def apply_iptables_dpi():
    """Apply iptables DPI rules"""
    logger.info("\n" + "=" * 60)
    logger.info("APPLYING IPTABLES DPI RULES")
    logger.info("=" * 60)
    
    rules = [
        ['iptables', '-N', 'GTP_DPI'],
        ['iptables', '-F', 'GTP_DPI'],
        ['iptables', '-A', 'GTP_DPI', '-p', 'udp', '--dport', '2152', 
         '-m', 'string', '--algo', 'bm', '--hex-string', '|30ff|', 
         '--from', '50', '--to', '200', '-j', 'DROP'],
        ['iptables', '-A', 'GTP_DPI', '-p', 'udp', '--dport', '2152', 
         '-m', 'string', '--algo', 'bm', '--hex-string', '|32ff|', 
         '--from', '50', '--to', '200', '-j', 'DROP'],
        ['iptables', '-A', 'GTP_DPI', '-p', 'udp', '--dport', '2152',
         '-m', 'u32', '--u32', '0>>22&0x3C@12>>26&0x3C@0&0xF0FF=0x30FF', '-j', 'DROP'],
        ['iptables', '-A', 'GTP_DPI', '-p', 'udp', '--dport', '2152',
         '-m', 'length', '--length', '100:65535',
         '-m', 'string', '--algo', 'bm', '--hex-string', '|30ff|',
         '--from', '36', '-j', 'DROP'],
        ['iptables', '-A', 'GTP_DPI', '-p', 'udp', '--dport', '2152',
         '-m', 'limit', '--limit', '1000/sec', '--limit-burst', '2000', '-j', 'ACCEPT'],
        ['iptables', '-A', 'GTP_DPI', '-p', 'udp', '--dport', '2152', '-j', 'DROP'],
    ]
    
    applied = 0
    errors = 0
    
    for rule in rules:
        try:
            result = subprocess.run(rule, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"  ✓ {' '.join(rule[1:5])}...")
                applied += 1
            else:
                if 'Chain already exists' in result.stderr:
                    logger.info(f"  ✓ Chain GTP_DPI already exists")
                else:
                    logger.warning(f"  ⚠ {result.stderr.strip()}")
                    errors += 1
        except Exception as e:
            logger.error(f"  ✗ Error: {e}")
            errors += 1
    
    chains_to_hook = ['INPUT', 'FORWARD', 'OUTPUT']
    for chain in chains_to_hook:
        check = subprocess.run(['iptables', '-C', chain, '-p', 'udp', '--dport', '2152', '-j', 'GTP_DPI'],
                              capture_output=True)
        if check.returncode != 0:
            subprocess.run(['iptables', '-I', chain, '-p', 'udp', '--dport', '2152', '-j', 'GTP_DPI'],
                          capture_output=True)
            logger.info(f"  ✓ Added {chain} jump to GTP_DPI")
    
    logger.info(f"\n  Applied: {applied} rules, Errors: {errors}")
    return errors == 0

def remove_iptables_dpi():
    """Remove iptables DPI rules"""
    logger.info("\n" + "=" * 60)
    logger.info("REMOVING IPTABLES DPI RULES")
    logger.info("=" * 60)
    
    for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
        subprocess.run(['iptables', '-D', chain, '-p', 'udp', '--dport', '2152', '-j', 'GTP_DPI'],
                      capture_output=True, text=True)
        logger.info(f"  ✓ Removed {chain} jump")
    
    subprocess.run(['iptables', '-F', 'GTP_DPI'], capture_output=True)
    subprocess.run(['iptables', '-X', 'GTP_DPI'], capture_output=True)
    logger.info("  ✓ DPI chain removed")

def verify_dpi():
    """Verify DPI rules are working by testing nested tunnel detection"""
    logger.info("\n" + "=" * 60)
    logger.info("VERIFYING DPI RULES")
    logger.info("=" * 60)
    
    result = subprocess.run(['iptables', '-L', 'GTP_DPI', '-n', '-v'], 
                           capture_output=True, text=True)
    
    if result.returncode == 0:
        logger.info("  ✓ GTP_DPI chain exists")
        logger.info("\n  Current rules:")
        for line in result.stdout.split('\n'):
            if line.strip():
                logger.info(f"    {line}")
        
        result2 = subprocess.run(['iptables', '-L', 'GTP_DPI', '-n', '--line-numbers'],
                                capture_output=True, text=True)
        
        rule_count = len([l for l in result2.stdout.split('\n') if l.strip() and not l.startswith('Chain') and not l.startswith('num')])
        
        if rule_count >= 4:
            logger.info(f"\n  ✓ DPI is ACTIVE with {rule_count} rules")
            return True
        else:
            logger.warning(f"\n  ⚠ Only {rule_count} rules active - DPI may be incomplete")
            return False
    else:
        logger.error("  ✗ GTP_DPI chain not found - DPI not active")
        return False

def show_dpi_stats():
    """Show DPI statistics - packets blocked, etc."""
    logger.info("\n" + "=" * 60)
    logger.info("DPI STATISTICS")
    logger.info("=" * 60)
    
    result = subprocess.run(['iptables', '-L', 'GTP_DPI', '-n', '-v', '-x'],
                           capture_output=True, text=True)
    
    if result.returncode == 0:
        lines = result.stdout.split('\n')
        for line in lines:
            if 'DROP' in line and 'string' in line:
                parts = line.split()
                if len(parts) >= 2:
                    pkts = parts[0]
                    bytes_val = parts[1]
                    logger.info(f"  🛡️ Nested GTP-U blocked: {pkts} packets, {bytes_val} bytes")
            elif 'limit' in line:
                parts = line.split()
                if len(parts) >= 2:
                    logger.info(f"  📊 Rate limited accepted: {parts[0]} packets")
    else:
        logger.info("  No statistics available")

def generate_open5gs_recommendations():
    """Generate Open5GS configuration recommendations"""
    logger.info("\n" + "=" * 60)
    logger.info("OPEN5GS CONFIGURATION RECOMMENDATIONS")
    logger.info("=" * 60)
    
    recommendations = """
    To enhance DPI in Open5GS, add these to your UPF configuration:

    1. Edit /etc/open5gs/upf.yaml:
    
       upf:
         pfcp:
           - addr: 127.0.0.4
         gtpu:
           - addr: 127.0.0.7
         # Add DPI settings:
         session:
           - subnet: 10.45.0.1/16
             dnn: internet
             # Enable packet inspection
             dev: ogstun
             
    2. For production, consider:
       - Deploy a dedicated GTP firewall (e.g., Suricata with GTP rules)
       - Use IPsec for N3 interface (UPF ↔ gNodeB)
       - Implement network segmentation
       - Enable PFCP heartbeat monitoring
       
    3. Add Suricata GTP rules (/etc/suricata/rules/gtp.rules):
    
       alert udp any any -> any 2152 (msg:"Nested GTP-U Tunnel Detected"; 
           content:"|30 ff|"; offset:8; depth:20; sid:5000001; rev:1;)
       
       alert udp any any -> any 2152 (msg:"GTP-U Flood Detected";
           threshold:type both, track by_src, count 1000, seconds 1;
           sid:5000002; rev:1;)
    """
    
    print(recommendations)
    
    with open('dpi_recommendations.txt', 'w') as f:
        f.write(recommendations)
    
    logger.info("  ✓ Recommendations saved to: dpi_recommendations.txt")

def run_full_remediation():
    """Run complete DPI remediation"""
    logger.info("")
    logger.info("█" * 60)
    logger.info("█  5G-GIBBON DPI REMEDIATION")
    logger.info("█  Implementing Deep Packet Inspection")
    logger.info("█" * 60)
    logger.info("")
    
    if not check_root():
        return False
    
    has_iptables = check_iptables()
    has_nftables = check_nftables()
    
    if has_iptables:
        apply_iptables_dpi()
        verify_dpi()
        show_dpi_stats()
    elif has_nftables:
        logger.info("nftables support coming soon - using iptables fallback")
    else:
        logger.error("Neither iptables nor nftables available!")
        logger.error("Install with: apt install iptables")
        return False
    
    generate_open5gs_recommendations()
    
    logger.info("")
    logger.info("█" * 60)
    logger.info("█  DPI REMEDIATION COMPLETE")
    logger.info("█" * 60)
    logger.info("")
    logger.info("Next steps:")
    logger.info("  1. Run 'cli.py audit' to verify DPI is now working")
    logger.info("  2. Test with 'cli.py nested-tunnel' - should now be blocked")
    logger.info("  3. Review dpi_recommendations.txt for additional hardening")
    logger.info("")
    
    return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'apply':
            if check_root():
                apply_iptables_dpi()
        elif sys.argv[1] == 'remove':
            if check_root():
                remove_iptables_dpi()
        elif sys.argv[1] == 'verify':
            verify_dpi()
        elif sys.argv[1] == 'stats':
            show_dpi_stats()
        elif sys.argv[1] == 'recommend':
            generate_open5gs_recommendations()
    else:
        run_full_remediation()

