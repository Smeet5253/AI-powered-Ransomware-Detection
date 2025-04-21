# # utils.py
# import numpy as np
# import pandas as pd
# import logging

# def setup_logger():
#     """Set up a logger for general use."""
#     logger = logging.getLogger("RansomwareUtils")
#     logger.setLevel(logging.INFO)
#     handler = logging.FileHandler("utils_log.txt")
#     formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)
#     return logger

# def normalize_data(data):
#     """Normalize the dataset using Min-Max scaling."""
#     return (data - data.min()) / (data.max() - data.min())

# def handle_missing_values(data):
#     """Handle missing values in the dataset."""
#     if data.isnull().sum().sum() > 0:
#         # Fill missing values with the mean of each column
#         data.fillna(data.mean(), inplace=True)
    
# def preprocess_data(filepath):
#     """Load and preprocess data from a CSV file."""
#     logger = setup_logger()
    
#     try:
#         data = pd.read_csv(filepath)
#         logger.info(f"Loaded data from {filepath}")
        
#         handle_missing_values(data)
#         logger.info("Handled missing values.")
        
#         normalized_data = normalize_data(data.select_dtypes(include=[np.number]))  # Normalize only numeric columns
#         logger.info("Normalized numeric data.")
        
#         return normalized_data
#     except Exception as e:
#         logger.error(f"Error during preprocessing: {e}")


# import pandas as pd
# from sklearn.preprocessing import StandardScaler

# # Function to preprocess the dataset
# def preprocess_data(filepath):
#     data = pd.read_csv(filepath)
#     # Drop non-feature columns
#     features = data.drop(['FileName', 'md5Hash', 'Benign'], axis=1)
#     labels = data['Benign']  # Target column
#     # Scale features
#     scaler = StandardScaler()
#     features = scaler.fit_transform(features)
#     return features, labels





# code 4: claude attempt 1
# utils.py
import os
import logging
import json
import psutil
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, List, Union, Tuple
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import sqlite3
from cryptography.fernet import Fernet

class SecurityUtils:
    def __init__(self):
        self.scaler = StandardScaler()
        self.setup_logging()
        self.setup_encryption()
        self.db_path = 'security_metrics.db'
        self.init_database()

    def setup_logging(self) -> None:
        """Configure secure logging system"""
        self.logger = logging.getLogger("SecurityUtils")
        self.logger.setLevel(logging.INFO)
        
        # Create encrypted log handler
        handler = logging.FileHandler("security_utils.log")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def setup_encryption(self) -> None:
        """Initialize encryption capabilities"""
        try:
            if os.path.exists('encryption_key.key'):
                with open('encryption_key.key', 'rb') as key_file:
                    self.key = key_file.read()
            else:
                self.key = Fernet.generate_key()
                with open('encryption_key.key', 'wb') as key_file:
                    key_file.write(self.key)
            
            self.cipher_suite = Fernet(self.key)
        except Exception as e:
            self.logger.error(f"Encryption setup error: {e}")

    def init_database(self) -> None:
        """Initialize SQLite database for metrics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        cpu_usage REAL,
                        memory_usage REAL,
                        disk_usage REAL,
                        network_traffic REAL
                    )
                ''')
                conn.commit()
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")

    def preprocess_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess and clean data"""
        try:
            # Handle missing values
            data.fillna(data.mean(), inplace=True)
            
            # Remove duplicates
            data.drop_duplicates(inplace=True)
            
            # Scale numerical features
            numerical_cols = data.select_dtypes(include=[np.number]).columns
            data[numerical_cols] = self.scaler.fit_transform(data[numerical_cols])
            
            return data
        except Exception as e:
            self.logger.error(f"Data preprocessing error: {e}")
            return None

    def collect_system_metrics(self) -> Dict[str, float]:
        """Collect current system metrics"""
        try:
            metrics = {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_traffic': sum(psutil.net_io_counters()[:2])  # sum of bytes sent and received
            }
            
            # Store metrics in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO system_metrics 
                    (timestamp, cpu_usage, memory_usage, disk_usage, network_traffic)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    metrics['cpu_usage'],
                    metrics['memory_usage'],
                    metrics['disk_usage'],
                    metrics['network_traffic']
                ))
                conn.commit()
            
            return metrics
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return None

    def analyze_file_properties(self, filepath: str) -> Dict[str, Union[str, int, float]]:
        """Analyze file properties for security assessment"""
        try:
            stats = os.stat(filepath)
            with open(filepath, 'rb') as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
                entropy = self.calculate_entropy(content)

            return {
                'size': stats.st_size,
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stats.st_atime).isoformat(),
                'hash': file_hash,
                'entropy': entropy
            }
        except Exception as e:
            self.logger.error(f"Error analyzing file {filepath}: {e}")
            return None

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0.0
            
            entropy = 0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy += -p_x * np.log2(p_x)
            return entropy
        except Exception as e:
            self.logger.error(f"Error calculating entropy: {e}")
            return None

    def encrypt_data(self, data: Union[str, bytes]) -> bytes:
        """Encrypt sensitive data"""
        try:
            if isinstance(data, str):
                data = data.encode()
            return self.cipher_suite.encrypt(data)
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            return None

    def decrypt_data(self, encrypted_data: bytes) -> Union[str, bytes]:
        """Decrypt encrypted data"""
        try:
            return self.cipher_suite.decrypt(encrypted_data)
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            return None

    def get_historical_metrics(self, hours: int = 24) -> pd.DataFrame:
        """Retrieve historical system metrics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = f"""
                    SELECT * FROM system_metrics 
                    WHERE timestamp > datetime('now', '-{hours} hours')
                    ORDER BY timestamp DESC
                """
                return pd.read_sql_query(query, conn)
        except Exception as e:
            self.logger.error(f"Error retrieving historical metrics: {e}")
            return None

    def generate_security_report(self) -> str:
        """Generate a comprehensive security report"""
        try:
            metrics_df = self.get_historical_metrics()
            if metrics_df is None:
                return "Error generating report: No data available"

            report = f"""
            Security Metrics Report
            Generated: {datetime.now().isoformat()}
            
            System Performance Summary (Last 24 Hours):
            {'-' * 50}
            CPU Usage (avg): {metrics_df['cpu_usage'].mean():.2f}%
            Memory Usage (avg): {metrics_df['memory_usage'].mean():.2f}%
            Disk Usage (avg): {metrics_df['disk_usage'].mean():.2f}%
            Network Traffic: {metrics_df['network_traffic'].sum()} bytes
            
            Peak Values:
            {'-' * 50}
            Peak CPU: {metrics_df['cpu_usage'].max():.2f}%
            Peak Memory: {metrics_df['memory_usage'].max():.2f}%
            Peak Disk: {metrics_df['disk_usage'].max():.2f}%
            """
            
            return report
        except Exception as e:
            self.logger.error(f"Error generating security report: {e}")
            return "Error generating security report"

if __name__ == "__main__":
    utils = SecurityUtils()
    
    # Example usage
    metrics = utils.collect_system_metrics()
    if metrics:
        print("Current System Metrics:", metrics)
    
    report = utils.generate_security_report()
    print("\nSecurity Report:", report)