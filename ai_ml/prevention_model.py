#code 3:---------------------------------------------------------------------------------------------------------
# prevention_model.py
# import requests

# class RansomwarePrevention:
#     def __init__(self):
#         self.threshold = 0.8

#     def predict_vulnerabilities(self, anomaly_scores):
#         return [score > self.threshold for score in anomaly_scores]

#     def enforce_mfa(self, user_credentials):
#         try:
#             response = requests.post("https://authservice.com/mfa", data=user_credentials)
#             response.raise_for_status()
#             return response.json()
#         except requests.exceptions.RequestException as e:
#             print(f"Error during MFA enforcement: {e}")
#             return None

#     def recommend_actions(self, threat_level):
#         if threat_level > self.threshold:
#             return [
#                 "Disconnect from the network.",
#                 "Perform a full system scan.",
#                 "Restore affected files from backup."
#             ]
#         else:
#             return ["No significant threats detected."]











#code 4: claude attempt 1 ======================================================================================
# prevention_model.py
import os
import logging
import json
import hashlib
import requests
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
import sqlite3
from threading import Lock

class EnhancedRansomwarePrevention:
    def __init__(self):
        self.db_path = 'prevention.db'
        self.lock = Lock()
        self.setup_logging()
        self.init_database()
        self.whitelist = self.load_whitelist()
        self.blacklist = self.load_blacklist()
        self.policy_rules = self.load_policy_rules()

    def setup_logging(self):
        """Configure logging for prevention activities"""
        self.logger = logging.getLogger("RansomwarePrevention")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler("prevention.log")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def init_database(self):
        """Initialize SQLite database for storing prevention data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_access_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        file_path TEXT,
                        process_name TEXT,
                        action TEXT,
                        status TEXT
                    )
                ''')
                conn.commit()
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")

    def load_whitelist(self) -> set:
        """Load whitelisted applications and processes"""
        try:
            with open('whitelist.json', 'r') as f:
                return set(json.load(f))
        except FileNotFoundError:
            return set(['explorer.exe', 'svchost.exe', 'system'])
        except Exception as e:
            self.logger.error(f"Error loading whitelist: {e}")
            return set()

    def load_blacklist(self) -> set:
        """Load known malicious file hashes and patterns"""
        try:
            with open('blacklist.json', 'r') as f:
                return set(json.load(f))
        except FileNotFoundError:
            return set()
        except Exception as e:
            self.logger.error(f"Error loading blacklist: {e}")
            return set()

    def load_policy_rules(self) -> Dict:
        """Load security policy rules"""
        try:
            with open('policy_rules.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'max_file_encryptions': 10,
                'suspicious_extensions': ['.encrypt', '.cry', '.crypto'],
                'protected_directories': ['Documents', 'Desktop']
            }
        except Exception as e:
            self.logger.error(f"Error loading policy rules: {e}")
            return {}

    def check_file_integrity(self, filepath: str) -> bool:
        """Verify file integrity using stored hashes"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            return file_hash not in self.blacklist
        except Exception as e:
            self.logger.error(f"Error checking file integrity: {e}")
            return False

    def monitor_file_operations(self, filepath: str, process_name: str, action: str) -> bool:
        """Monitor and log file operations"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO file_access_logs 
                    (timestamp, file_path, process_name, action, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    filepath,
                    process_name,
                    action,
                    'allowed' if process_name in self.whitelist else 'monitored'
                ))
                conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"Error logging file operation: {e}")
            return False

    def enforce_security_policies(self) -> bool:
        """Enforce configured security policies"""
        try:
            # Enable Windows Security Features
            if os.name == 'nt':
                subprocess.run(['powershell', 'Set-MpPreference', '-DisableRealtimeMonitoring', '$false'])
                subprocess.run(['powershell', 'Enable-WindowsOptionalFeature', '-Online', '-FeatureName', 'Microsoft-Windows-Subsystem-Linux'])

            # Set up filesystem monitoring
            for directory in self.policy_rules['protected_directories']:
                if os.name == 'nt':
                    subprocess.run(['icacls', directory, '/deny', 'Everyone:(WD)'])
                else:
                    subprocess.run(['chmod', '444', directory])

            self.logger.info("Security policies enforced successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error enforcing security policies: {e}")
            return False

    def analyze_process_behavior(self, process_name: str, pid: int) -> Dict:
        """Analyze process behavior for suspicious activities"""
        analysis = {
            'is_suspicious': False,
            'risk_level': 0.0,
            'reasons': []
        }

        try:
            # Check if process is whitelisted
            if process_name in self.whitelist:
                return analysis

            # Check process activities
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM file_access_logs 
                    WHERE process_name = ? AND timestamp > datetime('now', '-1 hour')
                ''', (process_name,))
                access_count = cursor.fetchone()[0]

                if access_count > self.policy_rules['max_file_encryptions']:
                    analysis['is_suspicious'] = True
                    analysis['risk_level'] = 0.8
                    analysis['reasons'].append('High frequency of file operations')

            return analysis
        except Exception as e:
            self.logger.error(f"Error analyzing process behavior: {e}")
            return analysis

    def implement_network_restrictions(self) -> bool:
        """Implement network-level restrictions"""
        try:
            if os.name == 'nt':  # Windows
                # Enable Windows Firewall
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'])
                # Block suspicious outbound connections
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                             'name="Block Suspicious Outbound"',
                             'dir=out', 'action=block',
                             'protocol=TCP', 'localport=445,137,138,139'])
            else:  # Linux
                # Configure iptables rules
                subprocess.run(['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '445', '-j', 'DROP'])
                subprocess.run(['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '137:139', '-j', 'DROP'])

            self.logger.info("Network restrictions implemented successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error implementing network restrictions: {e}")
            return False

    def generate_prevention_report(self) -> str:
        """Generate a comprehensive prevention status report"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*), status FROM file_access_logs 
                    WHERE timestamp > datetime('now', '-24 hours')
                    GROUP BY status
                ''')
                stats = cursor.fetchall()

            report = f"""
            Ransomware Prevention Report
            Generated: {datetime.now()}
            
            Last 24 Hours Statistics:
            {'-' * 50}
            """

            for count, status in stats:
                report += f"\n{status.title()} Operations: {count}"

            report += f"\n\nActive Protection Rules:"
            for rule, value in self.policy_rules.items():
                report += f"\n- {rule.replace('_', ' ').title()}: {value}"

            return report

        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return "Error generating prevention report"

if __name__ == "__main__":
    prevention = EnhancedRansomwarePrevention()
    
    # Example usage
    prevention.enforce_security_policies()
    prevention.implement_network_restrictions()
    
    # Monitor a file operation
    prevention.monitor_file_operations(
        "C:/example/file.txt",
        "notepad.exe",
        "write"
    )
    
    # Generate and print report
    report = prevention.generate_prevention_report()
    print(report)