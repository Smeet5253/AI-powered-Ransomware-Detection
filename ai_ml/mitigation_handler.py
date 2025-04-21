### Mitigation Attempt 1:  
### Mitigation is working But the risk score is 50% for all the files. This means that the model is not working properly. This is a very serious issue.

import os
import shutil
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any


class MitigationHandler:
    """
    Handles file quarantine, restoration, and mitigation strategies
    """
    def __init__(self, detector):
        """
        Initialize MitigationHandler
        
        Args:
            detector: The EnhancedRansomwareDetector instance
        """
        self.detector = detector
        self.logger = logging.getLogger("MitigationHandler")
        
        # Quarantine and backup directories
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.quarantine_dir = os.path.join(base_dir, 'quarantine')
        self.backup_dir = os.path.join(base_dir, 'backups')
        
        # Ensure directories exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Quarantine tracking file
        self.quarantine_log_path = os.path.join(
            self.quarantine_dir, 
            'quarantine_log.json'
        )
        
    def _load_quarantine_log(self) -> List[Dict[str, Any]]:
        """
        Load the quarantine log
        
        Returns:
            List of quarantined file entries
        """
        try:
            if os.path.exists(self.quarantine_log_path):
                with open(self.quarantine_log_path, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"Error loading quarantine log: {e}")
            return []
    
    def _save_quarantine_log(self, log_entries: List[Dict[str, Any]]):
        """
        Save the quarantine log
        
        Args:
            log_entries: List of quarantined file entries
        """
        try:
            with open(self.quarantine_log_path, 'w') as f:
                json.dump(log_entries, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving quarantine log: {e}")
    
    def quarantine_file(self, filepath: str) -> Dict[str, Any]:
        """
        Quarantine a potentially malicious file
        
        Args:
            filepath: Path to the file to quarantine
            
        Returns:
            Dictionary with quarantine result
        """
        try:
            # Ensure file exists
            if not os.path.exists(filepath):
                return {
                    'success': False,
                    'message': 'File does not exist'
                }
            
            # Calculate file hash
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Generate quarantine filename
            original_filename = os.path.basename(filepath)
            quarantine_filename = f"{file_hash}_{original_filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Move file to quarantine
            shutil.move(filepath, quarantine_path)
            
            # Create quarantine log entry
            quarantine_entry = {
                'hash': file_hash,
                'original_path': filepath,
                'original_name': original_filename,
                'quarantine_path': quarantine_path,
                'quarantine_time': datetime.now().isoformat(),
                'file_size': os.path.getsize(quarantine_path)
            }
            
            # Update quarantine log
            quarantine_log = self._load_quarantine_log()
            quarantine_log.append(quarantine_entry)
            self._save_quarantine_log(quarantine_log)
            
            self.logger.info(f"File quarantined: {quarantine_path}")
            
            return {
                'success': True,
                'message': 'File successfully quarantined',
                'details': quarantine_entry
            }
        
        except Exception as e:
            self.logger.error(f"Error quarantining file: {e}")
            return {
                'success': False,
                'message': f'Quarantine failed: {str(e)}'
            }
    
    def list_quarantined_files(self) -> List[Dict[str, Any]]:
        """
        List all quarantined files
        
        Returns:
            List of quarantined file details
        """
        return self._load_quarantine_log()
    
    def delete_from_quarantine(self, quarantine_hash: str) -> Dict[str, Any]:
        """
        Delete a file from quarantine
        
        Args:
            quarantine_hash: Hash of the quarantined file
            
        Returns:
            Dictionary with deletion result
        """
        try:
            quarantine_log = self._load_quarantine_log()
            
            # Find the file with the matching hash
            file_to_remove = None
            for entry in quarantine_log:
                if entry['hash'] == quarantine_hash:
                    file_to_remove = entry
                    break
            
            if not file_to_remove:
                return {
                    'success': False,
                    'message': 'File not found in quarantine'
                }
            
            # Remove file from filesystem
            quarantine_path = file_to_remove['quarantine_path']
            if os.path.exists(quarantine_path):
                os.unlink(quarantine_path)
            
            # Remove from log
            quarantine_log = [
                entry for entry in quarantine_log 
                if entry['hash'] != quarantine_hash
            ]
            self._save_quarantine_log(quarantine_log)
            
            self.logger.info(f"Deleted from quarantine: {quarantine_path}")
            
            return {
                'success': True,
                'message': 'File deleted from quarantine',
                'details': file_to_remove
            }
        
        except Exception as e:
            self.logger.error(f"Error deleting from quarantine: {e}")
            return {
                'success': False,
                'message': f'Deletion failed: {str(e)}'
            }
    
    def restore_from_quarantine(
        self, 
        quarantine_hash: str, 
        restore_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Restore a file from quarantine
        
        Args:
            quarantine_hash: Hash of the quarantined file
            restore_path: Optional path to restore the file to
            
        Returns:
            Dictionary with restoration result
        """
        try:
            quarantine_log = self._load_quarantine_log()
            
            # Find the file with the matching hash
            file_to_restore = None
            for entry in quarantine_log:
                if entry['hash'] == quarantine_hash:
                    file_to_restore = entry
                    break
            
            if not file_to_restore:
                return {
                    'success': False,
                    'message': 'File not found in quarantine'
                }
            
            quarantine_path = file_to_restore['quarantine_path']
            
            # Determine restore path
            if not restore_path:
                # Use original path if not specified
                restore_path = file_to_restore['original_path']
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            
            # Copy file from quarantine (keeping original in quarantine)
            shutil.copy2(quarantine_path, restore_path)
            
            # Create backup before any potential risks
            backup_path = os.path.join(
                self.backup_dir, 
                f"{file_to_restore['hash']}_{os.path.basename(restore_path)}"
            )
            shutil.copy2(restore_path, backup_path)
            
            self.logger.info(f"Restored file: {restore_path}")
            
            return {
                'success': True,
                'message': 'File restored successfully',
                'restore_path': restore_path,
                'backup_path': backup_path,
                'details': file_to_restore
            }
        
        except Exception as e:
            self.logger.error(f"Error restoring from quarantine: {e}")
            return {
                'success': False,
                'message': f'Restoration failed: {str(e)}'
            }
    
    def generate_mitigation_report(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate mitigation recommendations based on analysis results
        
        Args:
            analysis_result: Result from file analysis
            
        Returns:
            Dictionary with mitigation recommendations
        """
        # Default recommendations
        recommendations = []
        
        # High-risk recommendations
        if analysis_result['risk_score'] > 0.7:
            recommendations.extend([
                "Immediately isolate the file from the network",
                "Do not open or execute the file",
                "Scan with up-to-date antivirus software",
                "Create a backup of the system",
                "Consider reporting to security team",
                "Quarantine the suspicious file",
                "Investigate the file's origin"
            ])
        
        # Medium-risk recommendations
        elif analysis_result['risk_score'] > 0.4:
            recommendations.extend([
                "Exercise caution with this file",
                "Verify the source of the file",
                "Scan with antivirus before opening",
                "Consider restricting file access",
                "Monitor system for unusual activities",
                "Create a backup of potentially affected files"
            ])
        
        # Low-risk recommendations
        else:
            recommendations.extend([
                "File appears to be low risk",
                "Follow standard security practices",
                "Maintain up-to-date antivirus protection",
                "Periodically scan your system"
            ])
        
        # Add specific threats from analysis
        threats = analysis_result.get('threats', [])
        
        return {
            'risk_level': analysis_result.get('risk_level', 'unknown'),
            'risk_score': analysis_result.get('risk_score', 0),
            'recommendations': recommendations,
            'specific_threats': threats,
            'file_details': {
                'name': analysis_result.get('file_name', 'Unknown'),
                'type': analysis_result.get('file_type', 'Unknown'),
                'size': analysis_result.get('file_size', 0)
            }
        }