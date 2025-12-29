#!/usr/bin/env python3
"""
Add Test Subscriber to Open5GS
==============================
Creates a test subscriber with known keys for testing key extraction
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subprocess
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

TEST_SUBSCRIBER = {
    "imsi": "001010000000001",
    "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
    "opc": "E8ED289DEBA952E4283B54E88E6183CA",
    "amf": "8000",
    "sqn": "000000000000"
}

def add_subscriber_mongosh(imsi=None, k=None, opc=None):
    """Add subscriber using mongosh"""
    
    imsi = imsi or TEST_SUBSCRIBER["imsi"]
    k = k or TEST_SUBSCRIBER["k"]
    opc = opc or TEST_SUBSCRIBER["opc"]
    
    subscriber_doc = {
        "imsi": imsi,
        "msisdn": [],
        "imeisv": [],
        "mme_host": [],
        "mme_realm": [],
        "purge_flag": [],
        "security": {
            "k": k,
            "amf": TEST_SUBSCRIBER["amf"],
            "op": None,
            "opc": opc,
            "sqn": int(TEST_SUBSCRIBER["sqn"])
        },
        "ambr": {
            "downlink": {"value": 1, "unit": 3},
            "uplink": {"value": 1, "unit": 3}
        },
        "slice": [{
            "sst": 1,
            "default_indicator": True,
            "session": [{
                "name": "internet",
                "type": 3,
                "pcc_rule": [],
                "ambr": {
                    "downlink": {"value": 1, "unit": 3},
                    "uplink": {"value": 1, "unit": 3}
                },
                "qos": {
                    "index": 9,
                    "arp": {
                        "priority_level": 8,
                        "pre_emption_capability": 1,
                        "pre_emption_vulnerability": 1
                    }
                }
            }]
        }],
        "access_restriction_data": 32,
        "subscriber_status": 0,
        "network_access_mode": 0,
        "__v": 0
    }
    
    mongo_cmd = f'''
    db = db.getSiblingDB("open5gs");
    
    // Delete existing subscriber with same IMSI
    db.subscribers.deleteOne({{"imsi": "{imsi}"}});
    
    // Insert new subscriber
    db.subscribers.insertOne({json.dumps(subscriber_doc)});
    
    // Verify
    print("Inserted subscriber:");
    printjson(db.subscribers.findOne({{"imsi": "{imsi}"}}));
    '''
    
    logger.info(f"Adding test subscriber: IMSI={imsi}")
    logger.info(f"  K:   {k}")
    logger.info(f"  OPc: {opc}")
    
    try:
        result = subprocess.run(
            ['mongosh', '--quiet', '--eval', mongo_cmd],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0:
            logger.info("✓ Subscriber added successfully!")
            logger.info(f"Output: {result.stdout[:500]}")
            return True
        else:
            logger.error(f"Error: {result.stderr}")
            return False
            
    except FileNotFoundError:
        logger.info("mongosh not found, trying mongo...")
        try:
            result = subprocess.run(
                ['mongo', '--quiet', '--eval', mongo_cmd],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                logger.info("✓ Subscriber added successfully!")
                return True
        except:
            pass
    except Exception as e:
        logger.error(f"Error adding subscriber: {e}")
    
    return False

def list_subscribers():
    """List all subscribers in Open5GS"""
    
    mongo_cmd = '''
    db = db.getSiblingDB("open5gs");
    print("=== SUBSCRIBERS ===");
    db.subscribers.find().forEach(function(sub) {
        print("IMSI: " + sub.imsi);
        if (sub.security) {
            print("  K:   " + sub.security.k);
            print("  OPc: " + sub.security.opc);
            print("  AMF: " + sub.security.amf);
        }
        print("");
    });
    print("Total: " + db.subscribers.countDocuments() + " subscribers");
    '''
    
    try:
        result = subprocess.run(
            ['mongosh', '--quiet', '--eval', mongo_cmd],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0:
            print(result.stdout)
            return True
    except:
        pass
    
    return False

def delete_all_subscribers():
    """Delete all test subscribers"""
    
    mongo_cmd = '''
    db = db.getSiblingDB("open5gs");
    result = db.subscribers.deleteMany({});
    print("Deleted " + result.deletedCount + " subscribers");
    '''
    
    try:
        result = subprocess.run(
            ['mongosh', '--quiet', '--eval', mongo_cmd],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0:
            logger.info(result.stdout.strip())
            return True
    except Exception as e:
        logger.error(f"Error: {e}")
    
    return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "list":
            list_subscribers()
        elif sys.argv[1] == "delete":
            delete_all_subscribers()
        elif sys.argv[1] == "add":
            add_subscriber_mongosh()
    else:
        logger.info("Adding default test subscriber...")
        add_subscriber_mongosh()
        logger.info("\nVerifying:")
        list_subscribers()

