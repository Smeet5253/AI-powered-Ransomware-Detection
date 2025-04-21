#code 4: claude attempt 1 ===================================================================================
import os
import shutil
import logging
import json
from datetime import datetime
from typing import List, Dict
import subprocess
from threading import Lock

class EnhancedRansomwareMitigation:
    def __init__(self):
        self.quarantine_dir = 'quarantine'
        self.backup_dir = 'backups'
        self.lock = Lock()
        self.setup_directories()
        self.setup_logging()
        self.active_mitigations = set()

    def setup_directories(self):
        """Setup required directories for mitigation"""
        for directory in [self.quarantine_dir, self.backup_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def setup_logging(self):
        """Configure logging for mitigation actions"""
        self.logger = logging.getLogger("RansomwareMitigation")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler("mitigation.log")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def quarantine_file(self, filepath: str) -> bool:
        """Safely quarantine a suspicious file"""
        try:
            with self.lock:
                if not os.path.exists(filepath):
                    self.logger.error(f"File not found: {filepath}")
                    return False

                quarantine_path = os.path.join(
                    self.quarantine_dir,
                    f"{os.path.basename(filepath)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )

                # Create metadata for the quarantined file
                metadata = {
                    'original_path': filepath,
                    'quarantine_time': datetime.now().isoformat(),
                    'file_size': os.path.getsize(filepath),
                    'quarantine_path': quarantine_path
                }

                # Move file to quarantine
                shutil.move(filepath, quarantine_path)
                
                # Save metadata
                with open(f"{quarantine_path}.meta", 'w') as f:
                    json.dump(metadata, f)

                self.logger.info(f"Successfully quarantined file: {filepath}")
                return True

        except Exception as e:
            self.logger.error(f"Error quarantining file {filepath}: {e}")
            return False

    def create_backup(self, target_path: str) -> str:
        """Create a secure backup of the target"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(
                self.backup_dir,
                f"backup_{os.path.basename(target_path)}_{timestamp}"
            )

            if os.path.isfile(target_path):
                shutil.copy2(target_path, backup_path)
            else:
                shutil.copytree(target_path, backup_path)

            self.logger.info(f"Created backup: {backup_path}")
            return backup_path

        except Exception as e:
            self.logger.error(f"Backup failed for {target_path}: {e}")
            return None

    def isolate_system(self) -> bool:
        """Isolate the system from the network"""
        try:
            # Implementation will vary by OS
            if os.name == 'nt':  # Windows
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'])
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound'])
            else:  # Linux/Unix
                subprocess.run(['iptables', '-P', 'INPUT', 'DROP'])
                subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'])
                subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'])

            self.logger.info("System successfully isolated from network")
            return True

        except Exception as e:
            self.logger.error(f"Failed to isolate system: {e}")
            return False

    def kill_suspicious_process(self, pid: int) -> bool:
        """Terminate a suspicious process"""
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['taskkill', '/F', '/PID', str(pid)])
            else:  # Linux/Unix
                subprocess.run(['kill', '-9', str(pid)])

            self.logger.info(f"Successfully terminated process {pid}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to kill process {pid}: {e}")
            return False

    def restore_from_backup(self, backup_path: str, restore_path: str) -> bool:
        """Restore files from backup"""
        try:
            if os.path.isfile(backup_path):
                shutil.copy2(backup_path, restore_path)
            else:
                shutil.copytree(backup_path, restore_path)

            self.logger.info(f"Successfully restored from backup: {backup_path}")
            return True

        except Exception as e:
            self.logger.error(f"Restore failed: {e}")
            return False

    def execute_mitigation_plan(self, threat_info: Dict) -> Dict[str, bool]:
        """Execute a comprehensive mitigation plan based on threat information"""
        results = {
            'quarantine_successful': False,
            'backup_created': False,
            'system_isolated': False,
            'processes_terminated': False
        }

        # Quarantine suspicious files
        if threat_info.get('suspicious_files'):
            for file in threat_info['suspicious_files']:
                results['quarantine_successful'] = self.quarantine_file(file)

        # Create backup if risk is high
        if threat_info.get('risk_level', 0) > 0.7:
            backup_path = self.create_backup(threat_info.get('target_path'))
            results['backup_created'] = backup_path is not None

            # Isolate system for high-risk threats
            results['system_isolated'] = self.isolate_system()

        # Terminate suspicious processes
        if threat_info.get('suspicious_processes'):
            for pid in threat_info['suspicious_processes']:
                results['processes_terminated'] = self.kill_suspicious_process(pid)

        return results

    def generate_mitigation_report(self, mitigation_results: Dict) -> str:
        """Generate a detailed mitigation report"""
        report = f"""
        Ransomware Mitigation Report
        Generated: {datetime.now()}
        
        Actions Taken:
        {'-' * 50}
        """

        for action, success in mitigation_results.items():
            status = "✓ Successful" if success else "✗ Failed"
            report += f"\n{action.replace('_', ' ').title()}: {status}"

        return report

if __name__ == "__main__":
    mitigation = EnhancedRansomwareMitigation()
    
    # Example usage
    threat_info = {
        'suspicious_files': ['suspicious_file.exe'],
        'risk_level': 0.8,
        'target_path': '/path/to/important/files',
        'suspicious_processes': [1234, 5678]
    }
    
    results = mitigation.execute_mitigation_plan(threat_info)
    report = mitigation.generate_mitigation_report(results)
    print(report)