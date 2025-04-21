## 17th april Also 19th April: Working Fine
import os
import hashlib
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from datetime import datetime
import joblib
from typing import Dict, List, Tuple, Union, Optional

class RansomwareDetector:
    """
    Ransomware detection model using machine learning to analyze file characteristics
    and determine if they exhibit ransomware behavior.
    """
    def __init__(self):
        """Initialize the ransomware detector with a machine learning model"""
        self.setup_logging()
        
        # Create a RandomForestClassifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1  # Use all available cores
        )
        
        # Store model in the same directory as this file
        self.model_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_file = os.path.join(self.model_dir, 'ransomware_model.pkl')
        
        # Define suspicious strings that might indicate ransomware
        self.suspicious_strings = [
            b'ransom', b'bitcoin', b'encrypt', b'decrypt', b'btc', 
            b'payment', b'pay', b'money', b'files are encrypted', 
            b'your files', b'restore', b'restore files', b'key'
        ]
        
        # Try to load existing model
        self.load_model()

    def setup_logging(self) -> None:
        """Configure logging for the detector"""
        self.logger = logging.getLogger("RansomwareDetector")
        self.logger.setLevel(logging.INFO)
        
        # Ensure log directory exists
        os.makedirs('logs', exist_ok=True)
        
        # Create file handler
        handler = logging.FileHandler(os.path.join('logs', "detection.log"))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        self.logger.info("RansomwareDetector initialized")

    def load_data(self, filepath: str) -> Tuple[Optional[pd.DataFrame], Optional[pd.Series]]:
        """
        Load and preprocess training data from CSV
        
        Args:
            filepath: Path to the CSV dataset
            
        Returns:
            Tuple containing features and labels DataFrames
        """
        try:
            if not os.path.exists(filepath):
                self.logger.error(f"Dataset file not found: {filepath}")
                return None, None
                
            self.logger.info(f"Loading dataset from {filepath}")
            data = pd.read_csv(filepath)
            
            # Extract features and labels based on column presence
            if 'Benign' in data.columns:
                # Format expected in the original code
                labels = data['Benign']
                features = data.drop(['FileName', 'md5Hash', 'Benign'], axis=1, errors='ignore')
            elif 'class' in data.columns:
                # Alternative format
                labels = data['class']
                features = data.drop('class', axis=1, errors='ignore')
            else:
                self.logger.error("Could not identify label column in dataset")
                return None, None
                
            self.logger.info(f"Successfully loaded data with {len(features)} samples and {features.shape[1]} features")
            return features, labels
            
        except Exception as e:
            self.logger.error(f"Error loading data: {e}")
            return None, None

    def train_model(self, features: pd.DataFrame, labels: pd.Series) -> bool:
        """
        Train the ransomware detection model
        
        Args:
            features: DataFrame of features
            labels: Series of labels
            
        Returns:
            Boolean indicating success
        """
        try:
            if features is None or labels is None:
                self.logger.error("Cannot train model: features or labels are None")
                return False
                
            from sklearn.model_selection import train_test_split
            
            self.logger.info("Starting model training")
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=0.3, random_state=42
            )
            
            self.classifier.fit(X_train, y_train)
            self.logger.info("Model training completed successfully")
            
            # Evaluate model
            from sklearn.metrics import accuracy_score, classification_report
            y_pred = self.classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            self.logger.info(f"Model accuracy: {accuracy:.4f}")
            
            # Save model
            return self.save_model()
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False

    def save_model(self) -> bool:
        """
        Save model to file
        
        Returns:
            Boolean indicating success
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
            
            joblib.dump(self.classifier, self.model_file)
            self.logger.info(f"Model saved to {self.model_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            return False

    def load_model(self) -> bool:
        """
        Load model from file
        
        Returns:
            Boolean indicating success
        """
        try:
            if os.path.exists(self.model_file):
                self.classifier = joblib.load(self.model_file)
                self.logger.info(f"Model loaded from {self.model_file}")
                return True
            else:
                self.logger.warning(f"No model found at {self.model_file}")
                return False
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False

    def extract_features(self, filepath: str) -> np.ndarray:
        """
        Extract features from a file for analysis
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Array of extracted features
        """
        try:
            # Basic file stats
            file_stats = os.stat(filepath)
            file_size = file_stats.st_size
            
            # File extension
            _, file_extension = os.path.splitext(filepath)
            file_extension = file_extension.lower()
            
            # Calculate entropy (randomness)
            entropy = self._calculate_entropy(filepath)
            
            # Extension risk score
            extension_risk = self._calculate_extension_risk(file_extension)
            
            # Header analysis (simplified)
            contains_exe_header = self._check_exe_header(filepath)
            
            # Check for suspicious strings
            suspicious_score = self._check_suspicious_strings(filepath)
            
            # Time information
            modification_time = file_stats.st_mtime
            access_time = file_stats.st_atime
            creation_time = file_stats.st_ctime
            
            # Time since file creation (in seconds)
            now = datetime.now().timestamp()
            time_since_creation = now - creation_time
            time_since_modification = now - modification_time
            
            # Combine features into array
            features = np.array([
                file_size,
                entropy,
                extension_risk,
                int(contains_exe_header),
                suspicious_score,
                access_time - creation_time,
                modification_time - creation_time,
                time_since_creation,
                time_since_modification
            ])
            
            return features
        except Exception as e:
            self.logger.error(f"Error extracting features from {filepath}: {e}")
            return np.zeros(9)  # Return zeros array on error

    def _calculate_entropy(self, filepath: str, block_size: int = 4096) -> float:
        """
        Calculate Shannon entropy of file content
        
        Args:
            filepath: Path to the file
            block_size: Size of blocks to read
            
        Returns:
            Entropy value
        """
        try:
            # Read file
            with open(filepath, 'rb') as f:
                data = f.read(block_size)
                
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
                entropy -= probability * np.log2(probability)
                
            return entropy
        except Exception as e:
            self.logger.error(f"Error calculating entropy: {e}")
            return 0.0

    def _calculate_extension_risk(self, extension: str) -> float:
        """
        Assign risk score based on file extension
        
        Args:
            extension: File extension
            
        Returns:
            Risk score from 0.0 to 1.0
        """
        high_risk = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta']
        medium_risk = ['.zip', '.rar', '.7z', '.docm', '.xlsm', '.pptm', '.jar']
        suspicious_extensions = ['.crypted', '.crypt', '.encrypted', '.locked', '.enc']
        
        if extension in suspicious_extensions:
            return 0.9
        elif extension in high_risk:
            return 0.8
        elif extension in medium_risk:
            return 0.5
        else:
            return 0.2

    def _check_exe_header(self, filepath: str) -> bool:
        """
        Check if file has executable header (MZ)
        
        Args:
            filepath: Path to the file
            
        Returns:
            Boolean indicating if file has executable header
        """
        try:
            with open(filepath, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'
        except Exception:
            return False
    
    def _check_suspicious_strings(self, filepath: str) -> float:
        """
        Check for suspicious strings that might indicate ransomware
        
        Args:
            filepath: Path to the file
            
        Returns:
            Score based on suspicious strings found
        """
        try:
            with open(filepath, 'rb') as f:
                content = f.read(8192)  # Read first 8KB of file
            
            # Count occurrences of suspicious strings
            count = 0
            for suspicious in self.suspicious_strings:
                if suspicious in content.lower():
                    count += 1
            
            # Normalize score from 0 to 1
            return min(count / len(self.suspicious_strings), 1.0)
        except Exception as e:
            self.logger.error(f"Error checking suspicious strings: {e}")
            return 0.0

    def predict(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Predict if a sample is ransomware and return confidence
        
        Args:
            features: Array of features
            
        Returns:
            Tuple of (prediction, confidence)
        """
        try:
            # Check if model exists
            if not hasattr(self, 'classifier') or self.classifier is None:
                self.logger.error("No model available for prediction")
                
                # Fallback to heuristic method if no model available
                return self._heuristic_prediction(features)
                
            # Reshape features for single sample prediction
            features_reshaped = features.reshape(1, -1)
            
            # Make prediction
            prediction = self.classifier.predict(features_reshaped)[0]
            
            # Get probability (confidence)
            probabilities = self.classifier.predict_proba(features_reshaped)[0]
            
            # In our dataset, 1 means benign, 0 means malicious
            is_malicious = 1 - prediction  # Invert to make 1 = ransomware
            confidence = probabilities[int(not prediction)]  # Confidence of the prediction
            
            return int(is_malicious), float(confidence)
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            # Fallback to heuristic method
            return self._heuristic_prediction(features)
    
    def _heuristic_prediction(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Make a prediction based on heuristics when no model is available
        
        Args:
            features: Array of features
            
        Returns:
            Tuple of (prediction, confidence)
        """
        try:
            # Extract key features
            # entropy = features[1]
            extension_risk = features[2]
            has_exe_header = features[3]
            suspicious_score = features[4]
            
            # Calculate a simple risk score
            risk_score = (0.2 * extension_risk + 
                          0.3 * has_exe_header + 
                          0.5 * suspicious_score)
            
            # Classify as malicious if risk score is above threshold
            is_malicious = int(risk_score > 0.5)
            
            return is_malicious, risk_score
        except Exception as e:
            self.logger.error(f"Heuristic prediction error: {e}")
            return 0, 0.5  # Default to medium risk on error

    def analyze_file(self, filepath: str) -> Dict:
        """
        Comprehensive file analysis
        
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
                    'threats': ["File not found"],
                    'recommendations': ["Verify file path"],
                    'file_name': os.path.basename(filepath),
                    'file_size': 0
                }
                
            # Calculate hash
            file_hash = self.calculate_file_hash(filepath)
            
            # Extract features
            features = self.extract_features(filepath)
            
            # Make prediction with model if available
            is_malicious, risk_score = self.predict(features)
                
            # Determine threats and recommendations
            threats = []
            recommendations = []
            
            # File info
            file_name = os.path.basename(filepath)
            file_size = os.path.getsize(filepath)
            file_extension = os.path.splitext(filepath)[1].lower()
            
            # Add threats based on risk factors and analysis
            if risk_score > 0.7:
                threats.append("High risk file detected")
                if features[3] > 0:  # Has executable header
                    threats.append("File contains executable code")
                if features[4] > 0.3:  # Has suspicious strings
                    threats.append("File contains suspicious text patterns")
                if file_extension in ['.crypted', '.crypt', '.encrypted', '.locked', '.enc']:
                    threats.append(f"Suspicious file extension: {file_extension}")
                
                recommendations.append("Do not open or execute this file")
                recommendations.append("Scan with updated antivirus software")
                recommendations.append("Isolate file from network")
                recommendations.append("Verify the source of this file")
            elif risk_score > 0.4:
                threats.append("Moderate risk file detected")
                
                recommendations.append("Exercise caution with this file")
                recommendations.append("Verify source before opening")
                recommendations.append("Scan with antivirus before use")
            else:
                recommendations.append("File appears to be low risk")
                recommendations.append("Follow standard security practices")
                
            # Return results
            return {
                'hash': file_hash,
                'risk_score': float(risk_score),
                'threats': threats,
                'recommendations': recommendations,
                'file_name': file_name,
                'file_size': file_size
            }
        except Exception as e:
            self.logger.error(f"Error analyzing file {filepath}: {e}")
            return {
                'hash': None,
                'risk_score': 0.5,
                'threats': ["Error during analysis"],
                'recommendations': ["Try different analysis method"],
                'file_name': os.path.basename(filepath) if filepath else "Unknown",
                'file_size': 0
            }

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

# Example usage when run directly
if __name__ == "__main__":
    # Initialize detector
    detector = RansomwareDetector()
    
    # Look for dataset in common locations
    dataset_paths = [
        'ransomware_dataset.csv',
        '../ransomware_dataset.csv',
        '../../ransomware_dataset.csv',
    ]
    
    # Try to train model if dataset exists
    dataset_found = False
    for dataset_path in dataset_paths:
        if os.path.exists(dataset_path):
            print(f"Found dataset at {dataset_path}")
            features, labels = detector.load_data(dataset_path)
            if features is not None and labels is not None:
                print("Training model...")
                detector.train_model(features, labels)
                dataset_found = True
                break
    
    if not dataset_found:
        print("No dataset found. Using pre-trained model if available.")
    
    # Test on a sample file if provided as argument
    import sys
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        if os.path.exists(test_file):
            print(f"Analyzing file: {test_file}")
            results = detector.analyze_file(test_file)
            print(f"Risk score: {results['risk_score']:.2f}")
            print("Threats:", results['threats'])
            print("Recommendations:", results['recommendations'])
        else:
            print(f"File not found: {test_file}")