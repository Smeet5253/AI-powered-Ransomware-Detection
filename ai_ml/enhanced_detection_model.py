## ABove code is working fine without mitigation
### Mitigation Attempt 1:  
### Mitigation is working But the risk score is 50% for all the files. This means that the model is not working properly. This is a very serious issue.
import os
import hashlib
import logging
import math
import json
import pickle
import warnings
from datetime import datetime
from typing import Dict, List, Tuple, Union, Optional, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import ConvergenceWarning

# Suppress specific sklearn warnings
warnings.filterwarnings("ignore", category=ConvergenceWarning)
warnings.filterwarnings("ignore", category=UserWarning, message="X does not have valid feature names")

# Import MitigationHandler at the top of the file
from .mitigation_handler import MitigationHandler

class EnhancedRansomwareDetector:
    """
    Enhanced ransomware detection model using machine learning to analyze file 
    characteristics and determine if they exhibit ransomware behavior.
    """
    
    # Class constants
    VERSION = "1.2.0"
    MODEL_FILENAME = "ransomware_model.pkl"
    SCALER_FILENAME = "ransomware_scaler.pkl"
    FEATURE_NAMES_FILENAME = "feature_names.json"
    CONFIG_FILENAME = "detector_config.json"
    
    # Lists of suspicious patterns and high-risk extensions
    SUSPICIOUS_PATTERNS = [
        # Ransom notes and threats
        b"files have been encrypted", b"your files are encrypted", b"recover your files",
        b"pay the ransom", b"payment", b"decrypt your files", b"decryption key",
        b"bitcoin", b"btc", b"wallet", b"pay", b"ransom", b"decrypt", b"restore files",
        
        # Common ransomware names
        b"wannacry", b"petya", b"notpetya", b"locky", b"cerber", b"cryptolocker",
        b"cryptowall", b"jigsaw", b"badrabbit", b"ryuk", b"gandcrab", b"sodinokibi",
        b"revil", b"maze", b"darkside", b"blackmatter", b"lockbit", b"egregor",
        
        # File encryption indicators
        b"aes-256", b"rsa-2048", b"encrypted", b"locked", b"crypted",
        
        # Communication methods
        b"tor", b".onion", b"hidden service", b"contact us", b"contact"
    ]
    
    HIGH_RISK_EXTENSIONS = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta',
        '.scr', '.pif', '.msi', '.wsf', '.com'
    ]
    
    MEDIUM_RISK_EXTENSIONS = [
        '.zip', '.rar', '.7z', '.docm', '.xlsm', '.pptm', '.jar', '.chm'
    ]
    
    SUSPICIOUS_EXTENSIONS = [
        '.crypted', '.crypt', '.encrypted', '.locked', '.enc', '.crypto',
        '.locky', '.zepto', '.cerber', '.wncry', '.wcry', '.aesir', '.cerber3',
        '.osiris', '.wallet', '.damage', '.~lock', '.crypz', '.odin', '.zzzzz'
    ]
    
    # Default Feature Set from Ransomware Dataset
    DEFAULT_FEATURES = [
        'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 
        'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA', 
        'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections', 
        'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 
        'BitcoinAddresses'
    ]
    
    def __init__(self, model_dir: str = None, log_level: str = 'INFO'):
        """
        Initialize the enhanced ransomware detector
        
        Args:
            model_dir: Directory to store/load model files (default: script directory)
            log_level: Logging level (default: INFO)
        """
        # Setup logging
        self.logger = self._setup_logging(log_level)
        self.logger.info(f"Initializing EnhancedRansomwareDetector v{self.VERSION}")
        
        # Set model directory
        self.model_dir = model_dir if model_dir else os.path.dirname(os.path.abspath(__file__))
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Model file paths
        self.model_path = os.path.join(self.model_dir, self.MODEL_FILENAME)
        self.scaler_path = os.path.join(self.model_dir, self.SCALER_FILENAME)
        self.feature_names_path = os.path.join(self.model_dir, self.FEATURE_NAMES_FILENAME)
        self.config_path = os.path.join(self.model_dir, self.CONFIG_FILENAME)
        
        # Initialize model components
        self.classifier = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.feature_importances = None
        self.model_config = None
        self.train_stats = None
        
        # Load the model if available
        self.load_model()
        
        # Initialize mitigation handler
        self.mitigation_handler = MitigationHandler(self)
        
    def _setup_logging(self, level: str = 'INFO') -> logging.Logger:
        """
        Configure logging for the detector
        
        Args:
            level: Logging level
            
        Returns:
            Configured logger
        """
        logger = logging.getLogger("EnhancedRansomwareDetector")
        logger.setLevel(getattr(logging, level))
        
        # Ensure log directory exists
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Add file handler
        file_handler = logging.FileHandler(os.path.join(log_dir, "detection.log"))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger if they don't exist already
        if not logger.handlers:
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
        
        return logger
    
    def save_model(self) -> bool:
        """
        Save model and its components to files
        
        Returns:
            Boolean indicating success
        """
        try:
            # Save model
            if self.classifier:
                with open(self.model_path, 'wb') as f:
                    pickle.dump(self.classifier, f)
                self.logger.info(f"Model saved to {self.model_path}")
            
            # Save scaler
            if hasattr(self, 'scaler') and self.scaler is not None:
                with open(self.scaler_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
                self.logger.info(f"Scaler saved to {self.scaler_path}")
            
            # Save feature names
            if self.feature_names:
                with open(self.feature_names_path, 'w') as f:
                    json.dump(self.feature_names, f)
                self.logger.info(f"Feature names saved to {self.feature_names_path}")
            
            # Save model config and stats
            config_data = {
                'version': self.VERSION,
                'train_date': datetime.now().isoformat(),
                'feature_importances': self.feature_importances,
                'train_stats': self.train_stats,
                'model_config': self.model_config
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self) -> bool:
        """
        Load model and its components from files
        
        Returns:
            Boolean indicating success
        """
        try:
            # Load model if it exists
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.classifier = pickle.load(f)
                self.logger.info(f"Model loaded from {self.model_path}")
                
                # Load scaler if it exists
                if os.path.exists(self.scaler_path):
                    with open(self.scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                    self.logger.info(f"Scaler loaded from {self.scaler_path}")
                
                # Load feature names if they exist
                if os.path.exists(self.feature_names_path):
                    with open(self.feature_names_path, 'r') as f:
                        self.feature_names = json.load(f)
                    self.logger.info(f"Feature names loaded from {self.feature_names_path}")
                else:
                    # Use default feature names if file doesn't exist
                    self.feature_names = self.DEFAULT_FEATURES
                    self.logger.warning(f"Feature names file not found, using default feature set")
                
                # Load model config if it exists
                if os.path.exists(self.config_path):
                    with open(self.config_path, 'r') as f:
                        config_data = json.load(f)
                        self.feature_importances = config_data.get('feature_importances')
                        self.train_stats = config_data.get('train_stats')
                        self.model_config = config_data.get('model_config')
                    self.logger.info(f"Model configuration loaded from {self.config_path}")
                
                return True
            else:
                self.logger.warning(f"No model found at {self.model_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
    
    def load_data(self, filepath: str) -> Tuple[Optional[pd.DataFrame], Optional[pd.Series]]:
        """
        Load and preprocess the dataset for training - Compatibility with original RansomwareDetector
        
        Args:
            filepath: Path to CSV dataset
            
        Returns:
            Tuple of features and labels
        """
        return self.load_dataset(filepath)
    
    def load_dataset(self, filepath: str) -> Tuple[Optional[pd.DataFrame], Optional[pd.Series]]:
        """
        Load and preprocess the dataset for training
        
        Args:
            filepath: Path to CSV dataset
            
        Returns:
            Tuple of features and labels
        """
        try:
            if not os.path.exists(filepath):
                self.logger.error(f"Dataset file not found: {filepath}")
                return None, None
            
            self.logger.info(f"Loading dataset from {filepath}")
            data = pd.read_csv(filepath)
            
            # Print dataset info
            self.logger.info(f"Dataset shape: {data.shape}")
            self.logger.info(f"Dataset columns: {data.columns.tolist()}")
            
            # Check for label column
            if 'Benign' in data.columns:
                # In our dataset, 1 = benign, 0 = malicious
                labels = data['Benign']
                
                # Drop non-feature columns
                features = data.drop(['FileName', 'md5Hash', 'Benign'], axis=1, errors='ignore')
                
                # Save feature names for future use
                self.feature_names = features.columns.tolist()
                
                # Check for missing values
                missing_count = features.isnull().sum().sum()
                if missing_count > 0:
                    self.logger.warning(f"Dataset contains {missing_count} missing values. Imputing...")
                    # Simple imputation for now - we'll use median for numeric data
                    for col in features.columns:
                        if features[col].isnull().any():
                            features[col] = features[col].fillna(features[col].median())
                
                # Log dataset stats
                self.logger.info(f"Dataset distribution: Benign={sum(labels == 1)}, Malicious={sum(labels == 0)}")
                self.logger.info(f"Dataset loaded successfully: {len(features)} samples, {len(features.columns)} features")
                
                return features, labels
            else:
                self.logger.error("Required column 'Benign' not found in dataset")
                return None, None
                
        except Exception as e:
            self.logger.error(f"Error loading dataset: {e}")
            return None, None
    
    def train_model(self, 
                    features: pd.DataFrame, 
                    labels: pd.Series,
                    tune_hyperparams: bool = False) -> bool:
        """
        Train the ransomware detection model with advanced techniques
        
        Args:
            features: DataFrame of features
            labels: Series of labels (1 = benign, 0 = malicious)
            tune_hyperparams: Whether to perform hyperparameter tuning
            
        Returns:
            Boolean indicating success
        """
        try:
            if features is None or labels is None:
                self.logger.error("Cannot train model: features or labels are None")
                return False
            
            self.logger.info("Starting model training")
            
            # Store feature names
            self.feature_names = features.columns.tolist()
            
            # Create train/test split with stratification
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Create model - we'll use a RandomForestClassifier for better interpretability
            # If hyperparameter tuning is requested, perform grid search
            if tune_hyperparams:
                self.logger.info("Performing hyperparameter tuning")
                param_grid = {
                    'n_estimators': [100, 200],
                    'max_depth': [10, 20, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4],
                    'class_weight': [None, 'balanced']
                }
                
                # Use StratifiedKFold for better balance
                cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
                
                # Create grid search
                grid_search = GridSearchCV(
                    RandomForestClassifier(random_state=42),
                    param_grid,
                    cv=cv,
                    scoring='f1',
                    n_jobs=-1
                )
                
                # Fit grid search
                grid_search.fit(X_train_scaled, y_train)
                
                # Get best model
                self.classifier = grid_search.best_estimator_
                self.model_config = grid_search.best_params_
                self.logger.info(f"Best parameters: {grid_search.best_params_}")
            else:
                # Default model without tuning
                self.classifier = RandomForestClassifier(
                    n_estimators=200,
                    max_depth=None,
                    min_samples_split=2,
                    min_samples_leaf=1,
                    class_weight='balanced',
                    random_state=42,
                    n_jobs=-1
                )
                self.model_config = {
                    'n_estimators': 200,
                    'max_depth': None,
                    'min_samples_split': 2,
                    'min_samples_leaf': 1,
                    'class_weight': 'balanced'
                }
                
                # Train model
                self.classifier.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.classifier.predict(X_test_scaled)
            y_proba = self.classifier.predict_proba(X_test_scaled)[:, 1]  # Probability of benign class
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            # Calculate AUC - for malicious detection
            # In our dataset 0 = malicious, 1 = benign, so we need to flip for AUC
            auc = roc_auc_score(1 - y_test, 1 - y_proba)
            
            # Store training stats
            self.train_stats = {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1': float(f1),
                'auc': float(auc),
                'train_samples': len(X_train),
                'test_samples': len(X_test),
                'benign_count': int(sum(labels == 1)),
                'malicious_count': int(sum(labels == 0))
            }
            
            # Store feature importances
            self.feature_importances = dict(zip(
                self.feature_names, 
                self.classifier.feature_importances_
            ))
            
            # Log evaluation results
            self.logger.info(f"Model training completed successfully")
            self.logger.info(f"Model accuracy: {accuracy:.4f}")
            self.logger.info(f"Model precision: {precision:.4f}")
            self.logger.info(f"Model recall: {recall:.4f}")
            self.logger.info(f"Model F1 score: {f1:.4f}")
            self.logger.info(f"Model AUC: {auc:.4f}")
            
            # Get top 5 most important features
            sorted_importances = sorted(self.feature_importances.items(), key=lambda x: x[1], reverse=True)
            self.logger.info("Top 5 important features:")
            for feature, importance in sorted_importances[:5]:
                self.logger.info(f"  {feature}: {importance:.4f}")
            
            # Save the model
            return self.save_model()
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False
    
    def calculate_entropy(self, data: bytes, block_size: int = 8192) -> float:
        """
        Calculate Shannon entropy of file content
        
        Args:
            data: Bytes to analyze
            block_size: Size of data to analyze
            
        Returns:
            Entropy value between 0 and 8
        """
        try:
            # If data is larger than block_size, use only first block
            if len(data) > block_size:
                data = data[:block_size]
                
            if not data:
                return 0.0
                
            # Count byte frequencies
            byte_counts = {}
            for byte in data:
                if byte not in byte_counts:
                    byte_counts[byte] = 0
                byte_counts[byte] += 1
                
            # Calculate entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
                
            return entropy
        except Exception as e:
            self.logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """
        Comprehensive file analysis for ransomware detection
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Dictionary with analysis results
        """
        try:
            # Verify file exists
            if not os.path.exists(filepath):
                return {
                    'hash': None,
                    'risk_score': 0.5,
                    'risk_level': 'medium',
                    'threats': ["File not found"],
                    'recommendations': ["Verify file path"],
                    'file_name': os.path.basename(filepath),
                    'file_size': 0
                }
            
            # Extract file features
            file_info = self.extract_file_features(filepath)
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(filepath)
            
            # Prepare features for the model
            model_features = self.prepare_model_features(file_info)
            
            # Make prediction
            is_ransomware, risk_score, explanation = self.predict(model_features, file_info)
            
            # Determine risk level
            if risk_score > 0.7:
                risk_level = "high"
            elif risk_score > 0.4:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Generate threats based on risk level and explanation
            threats = []
            recommendations = []
            
            if risk_level == "high":
                threats.append("High risk file detected")
                
                # Add specific threats based on detection factors
                if file_info['is_pe_file']:
                    threats.append("File contains executable code")
                
                if file_info['suspicious_count'] > 0:
                    threats.append(f"File contains {file_info['suspicious_count']} suspicious patterns")
                    if len(file_info['suspicious_matches']) > 0:
                        top_matches = file_info['suspicious_matches'][:3]
                        threats.append(f"Suspicious content includes: {', '.join(top_matches)}")
                
                if file_info['entropy'] > 7.0:
                    threats.append("File has high entropy (possible encryption)")
                
                if file_info['extension_risk'] > 0.7:
                    threats.append(f"High-risk file extension: {file_info['file_extension']}")
                
                # Recommendations for high risk
                recommendations.append("Do not open or execute this file")
                recommendations.append("Scan with updated antivirus software")
                recommendations.append("Isolate file from network")
                recommendations.append("Report to security team")
                
            elif risk_level == "medium":
                threats.append("Moderate risk file detected")
                
                # Add specific threats
                if file_info['suspicious_count'] > 0:
                    threats.append("File contains some suspicious patterns")
                
                if file_info['entropy'] > 6.5:
                    threats.append("File has moderately high entropy")
                
                if file_info['is_pe_file']:
                    threats.append("File contains executable code")
                
                # Recommendations for medium risk
                recommendations.append("Exercise caution with this file")
                recommendations.append("Verify source before opening")
                recommendations.append("Scan with antivirus before use")
                
            else:
                # Low risk
                if file_info['is_pe_file']:
                    threats.append("Executable file with low risk assessment")
                    recommendations.append("Still recommended to verify the source")
                else:
                    recommendations.append("File appears to be low risk")
                    recommendations.append("Follow standard security practices")
            
            # Create detailed result
            result = {
                'hash': file_hash,
                'risk_score': float(risk_score),
                'risk_level': risk_level,
                'threats': threats,
                'recommendations': recommendations,
                'file_name': os.path.basename(filepath),
                'file_size': file_info['file_size'],
                'file_type': file_info['file_extension'],
                'entropy': file_info['entropy'],
                'detection_factors': explanation,
                'analysis_time': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {filepath}: {e}")
            return {
                'hash': None,
                'risk_score': 0.5,
                'risk_level': 'medium',
                'threats': ["Error during analysis"],
                'recommendations': ["Try different analysis method"],
                'file_name': os.path.basename(filepath) if filepath else "Unknown",
                'file_size': 0,
                'error': str(e)
            }
    
    def check_suspicious_patterns(self, data: bytes) -> Tuple[int, List[str]]:
        """
        Check if file contains suspicious patterns
        
        Args:
            data: File content
            
        Returns:
            Tuple of (count of matches, list of matched patterns)
        """
        try:
            lower_data = data.lower()
            matches = []
            
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern in lower_data:
                    matches.append(pattern.decode('utf-8', errors='ignore'))
            
            return len(matches), matches
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious patterns: {e}")
            return 0, []
    
    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            filepath: Path to the file
            
        Returns:
            Hash string
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {filepath}: {e}")
            return None
    
    def calculate_extension_risk(self, extension: str) -> float:
        """
        Calculate risk score based on file extension
        
        Args:
            extension: File extension (with dot)
            
        Returns:
            Risk score between 0 and 1
        """
        extension = extension.lower() if extension else ''
        
        if extension in self.SUSPICIOUS_EXTENSIONS:
            return 0.9  # Very high risk
        elif extension in self.HIGH_RISK_EXTENSIONS:
            return 0.7  # High risk
        elif extension in self.MEDIUM_RISK_EXTENSIONS:
            return 0.4  # Medium risk
        else:
            return 0.1  # Low risk
    
    def check_pe_header(self, data: bytes) -> bool:
        """
        Check if file has PE header (starts with MZ)
        
        Args:
            data: File content
            
        Returns:
            Boolean indicating if file is a PE file
        """
        try:
            return len(data) >= 2 and data[:2] == b'MZ'
        except Exception as e:
            self.logger.error(f"Error checking PE header: {e}")
            return False
    
    def extract_file_features(self, filepath: str) -> Dict[str, Any]:
        """
        Extract file features for analysis that align with the model's expected features
        
        Args:
            filepath: Path to the file
            
        Returns:
            Dictionary with extracted features
        """
        try:
            # Read file data (first 8KB for quick analysis)
            with open(filepath, 'rb') as f:
                data = f.read(8192)
            
            # Get file stats
            file_stats = os.stat(filepath)
            file_size = file_stats.st_size
            
            # Extract file extension
            _, file_extension = os.path.splitext(filepath)
            
            # Calculate entropy
            entropy = self.calculate_entropy(data)
            
            # Check for suspicious patterns
            suspicious_count, suspicious_matches = self.check_suspicious_patterns(data)
            
            # Check if file is a PE file
            is_pe_file = self.check_pe_header(data)
            
            # Build a features dictionary
            file_info = {
                'file_path': filepath,
                'file_name': os.path.basename(filepath),
                'file_size': file_size,
                'file_extension': file_extension.lower(),
                'is_pe_file': is_pe_file,
                'entropy': entropy,
                'extension_risk': self.calculate_extension_risk(file_extension),
                'suspicious_count': suspicious_count,
                'suspicious_matches': suspicious_matches,
                'created_time': file_stats.st_ctime,
                'modified_time': file_stats.st_mtime,
                'accessed_time': file_stats.st_atime
            }
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error extracting file features: {e}")
            return {
                'file_path': filepath,
                'file_name': os.path.basename(filepath),
                'file_size': 0,
                'file_extension': '',
                'is_pe_file': False,
                'entropy': 0,
                'extension_risk': 0,
                'suspicious_count': 0,
                'suspicious_matches': [],
                'created_time': 0,
                'modified_time': 0,
                'accessed_time': 0
            }
    
    def prepare_model_features(self, file_info: Dict[str, Any]) -> np.ndarray:
        """
        Prepare features for the model based on file information
        
        Args:
            file_info: Dictionary with file information
            
        Returns:
            Numpy array of features in the format expected by the model
        """
        try:
            # Check if we have feature names from the model
            if not self.feature_names:
                self.logger.warning("No feature names found, using default feature set")
                self.feature_names = self.DEFAULT_FEATURES
            
            # Initialize feature vector with zeros
            feature_vector = np.zeros(len(self.feature_names))
            
            # For PE files, we can extract more meaningful features
            is_pe = file_info['is_pe_file']
            
            # Map our extracted features to the model's expected features
            # We use safer default values for non-PE files
            feature_map = {}
            
            # Build feature map based on dataset columns
            for feature_name in self.feature_names:
                if feature_name == 'Machine':
                    # Common values: 332 for x86, 34404 for x64
                    feature_map[feature_name] = 332 if is_pe else 0
                
                elif feature_name == 'NumberOfSections':
                    # PE files typically have 3+ sections, non-PE files get 1
                    feature_map[feature_name] = 4 if is_pe else 1
                
                elif feature_name == 'SizeOfStackReserve':
                    # Use file size as a proxy for this
                    feature_map[feature_name] = min(file_info['file_size'], 1000000)
                
                elif feature_name == 'BitcoinAddresses':
                    # Check if any suspicious patterns contain bitcoin-related strings
                    bitcoin_related = any('bitcoin' in m.lower() or 'btc' in m.lower() 
                                         for m in file_info['suspicious_matches'])
                    feature_map[feature_name] = 1 if bitcoin_related else 0
                
                elif feature_name == 'ResourceSize':
                    # Estimate resource size based on file size for PE files
                    feature_map[feature_name] = min(file_info['file_size'] // 10, 10000) if is_pe else 0
                
                elif feature_name == 'MajorOSVersion':
                    feature_map[feature_name] = 6 if is_pe else 0
                
                elif feature_name == 'MajorLinkerVersion':
                    feature_map[feature_name] = 14 if is_pe else 0
                
                elif feature_name == 'MinorLinkerVersion':
                    feature_map[feature_name] = 0
                    
                # Default case for other features
                else:
                    feature_map[feature_name] = 0
            
            # Convert feature map to array in the correct order
            for i, feature_name in enumerate(self.feature_names):
                feature_vector[i] = feature_map.get(feature_name, 0)
            
            # Return the feature vector in the shape expected by the model
            return feature_vector
        
        except Exception as e:
            self.logger.error(f"Error preparing model features: {e}")
            # Return zeros with the correct length
            return np.zeros(len(self.feature_names) if self.feature_names else len(self.DEFAULT_FEATURES))
    
    def predict(self, features: np.ndarray, file_info: Dict[str, Any]) -> Tuple[int, float, Dict]:
        """
        Predict if a file is ransomware
        
        Args:
            features: Feature array prepared for the model
            file_info: Additional file information for heuristic evaluation
            
        Returns:
            Tuple of (is_ransomware, risk_score, explanation)
        """
        try:
            # If we don't have a trained model, use heuristic-only approach
            if self.classifier is None:
                return self._heuristic_prediction(file_info)
            
            # Prepare features for prediction
            features_reshaped = features.reshape(1, -1)
            
            # Apply scaling if we have a scaler
            if self.scaler is not None:
                try:
                    features_scaled = self.scaler.transform(features_reshaped)
                except:
                    self.logger.warning("Scaling error, using unscaled features")
                    features_scaled = features_reshaped
            else:
                features_scaled = features_reshaped
            
            # Make prediction
            try:
                prediction = self.classifier.predict(features_scaled)[0]
                probabilities = self.classifier.predict_proba(features_scaled)[0]
                
                # In our dataset: 1 = benign, 0 = malicious
                is_ransomware = int(prediction == 0)  # 1 if malicious (0), 0 if benign (1)
                
                # Get probability of the predicted class
                if is_ransomware:
                    # If predicted as ransomware (class 0), get its probability
                    confidence = probabilities[0]
                else:
                    # If predicted as benign (class 1), get its probability
                    confidence = probabilities[1]
                
                # Final risk score calculation
                # For ransomware: risk_score = malicious_probability
                # For benign: risk_score = malicious_probability (not inverted)
                risk_score = probabilities[0]  # Probability of being malicious
                
                # Apply file type adjustments - lower the risk for non-executable files
                if not file_info['is_pe_file'] and file_info['file_extension'] not in self.HIGH_RISK_EXTENSIONS:
                    # For non-executables, we reduce the risk unless there's strong evidence
                    if risk_score < 0.8:  # If not extremely high risk
                        risk_score *= 0.7  # Reduce risk by 30%
                
                # Generate explanation
                explanation = self._generate_explanation(features, file_info, is_ransomware, risk_score, probabilities)
                
                return is_ransomware, risk_score, explanation
                
            except Exception as e:
                self.logger.error(f"Model prediction error: {e}")
                # Fall back to heuristic prediction
                return self._heuristic_prediction(file_info)
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return self._heuristic_prediction(file_info)
    
    def _heuristic_prediction(self, file_info: Dict[str, Any]) -> Tuple[int, float, Dict[str, float]]:
        """
        Make a prediction based on heuristics when model fails
        
        Args:
            file_info: Dictionary with file information
            
        Returns:
            Tuple of (is_ransomware, risk_score, explanation)
        """
        try:
            # Initialize risk factors and scores
            risk_factors = {}
            total_risk_score = 0.0
            
            # Check file extension
            extension_risk = file_info['extension_risk']
            risk_factors['file_extension'] = extension_risk
            total_risk_score += extension_risk * 0.3  # 30% weight
            
            # Check for PE header
            if file_info['is_pe_file']:
                is_pe_risk = 0.4
                risk_factors['is_executable'] = is_pe_risk
                total_risk_score += is_pe_risk
            else:
                risk_factors['is_executable'] = 0.0
            
            # Check entropy (high entropy can indicate encryption)
            entropy = file_info['entropy']
            entropy_normalized = min(entropy / 8.0, 1.0)  # Normalize to 0-1
            if entropy_normalized > 0.7:  # High entropy
                entropy_risk = 0.2 * entropy_normalized
                risk_factors['high_entropy'] = entropy_risk
                total_risk_score += entropy_risk
            else:
                risk_factors['high_entropy'] = 0.0
            
            # Check for suspicious strings
            suspicious_count = file_info['suspicious_count']
            if suspicious_count > 0:
                suspicious_risk = min(suspicious_count * 0.1, 0.5)  # Cap at 0.5
                risk_factors['suspicious_content'] = suspicious_risk
                total_risk_score += suspicious_risk
                
                # Check for bitcoin-related patterns specifically
                bitcoin_related = any('bitcoin' in m.lower() or 'btc' in m.lower() 
                                     for m in file_info['suspicious_matches'])
                if bitcoin_related:
                    bitcoin_risk = 0.3
                    risk_factors['bitcoin_related'] = bitcoin_risk
                    total_risk_score += bitcoin_risk
                else:
                    risk_factors['bitcoin_related'] = 0.0
            else:
                risk_factors['suspicious_content'] = 0.0
                risk_factors['bitcoin_related'] = 0.0
            
            # Calculate final risk score (cap at 1.0)
            risk_score = min(total_risk_score, 1.0)
            
            # Determine if it's ransomware based on threshold
            is_ransomware = int(risk_score > 0.5)
            
            return is_ransomware, risk_score, risk_factors
            
        except Exception as e:
            self.logger.error(f"Heuristic prediction error: {e}")
            return 0, 0.5, {"error": 1.0}
        
    def _generate_explanation(self, features: np.ndarray, file_info: Dict[str, Any], 
                             prediction: int, risk_score: float, 
                             probabilities: np.ndarray) -> Dict[str, float]:
        """
        Generate explanation for prediction result
        
        Args:
            features: Feature array
            file_info: File information dictionary
            prediction: Model prediction (1 = ransomware, 0 = benign)
            risk_score: Calculated risk score
            probabilities: Model prediction probabilities
            
        Returns:
            Dictionary with explanation factors and their weights
        """
        try:
            explanation = {}
            
            # If we have feature importances, use them for explanation
            if self.feature_importances and self.feature_names:
                # Get the top contributing features
                feature_contributions = {}
                
                for i, feature_name in enumerate(self.feature_names):
                    importance = self.feature_importances.get(feature_name, 0)
                    feature_val = features[i]
                    
                    # Only include non-zero features
                    if importance > 0 and feature_val > 0:
                        feature_contributions[feature_name] = float(importance * feature_val)
                
                # Sort by contribution and take top 5
                sorted_contributions = sorted(
                    feature_contributions.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]
                
                for feature, contribution in sorted_contributions:
                    explanation[feature] = contribution
            
            # Add heuristic factors to the explanation
            if file_info['is_pe_file']:
                explanation['executable_file'] = 0.4
            
            if file_info['extension_risk'] > 0.5:
                explanation['high_risk_extension'] = file_info['extension_risk']
            
            entropy_normalized = min(file_info['entropy'] / 8.0, 1.0)
            if entropy_normalized > 0.7:
                explanation['high_entropy'] = entropy_normalized * 0.2
            
            if file_info['suspicious_count'] > 0:
                explanation['suspicious_patterns'] = min(file_info['suspicious_count'] * 0.1, 0.5)
            
            # Add model confidence if available
            if len(probabilities) >= 2:
                explanation['model_confidence'] = float(max(probabilities))
            
            return explanation
            
        except Exception as e:
            self.logger.error(f"Error generating explanation: {e}")
            return {"error_generating_explanation": 1.0}