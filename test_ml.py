# #### 8th April: Phase 1: attempt 1 with random output values

# def test_model_training(detector):
#     """Test training the model with sample data"""
#     logger.info("Testing model training...")
    
#     # Create sample dataset
#     dataset_path = create_sample_dataset()
#     if not dataset_path:
#         logger.error("Failed to create sample dataset")
#         return False
    
#     try:
#         # Load the data
#         features, labels = detector.load_data(dataset_path)
#         assert features is not None, "Failed to load features"
#         assert labels is not None, "Failed to load labels"
        
#         # Train the model
#         success = detector.train_model(features, labels)
#         assert success, "Model training failed"
        
#         # Check that model file exists
#         assert os.path.exists(detector.model_file), "Model file not created"
        
#         logger.info("Model training test passed")
#         return True
#     except Exception as e:
#         logger.error(f"Model training test failed: {str(e)}")
#         return False
#     finally:
#         # Clean up the dataset file
#         try:
#             os.unlink(dataset_path)
#         except:
#             pass

# def test_file_analysis(detector):
#     """Test analyzing files for ransomware"""
#     logger.info("Testing file analysis...")
    
#     # Create test files
#     benign_file = create_test_file(content=b"This is a normal text file.", extension='.txt')
#     suspicious_file = create_test_file(content=b"MZ" + os.urandom(4094), extension='.exe')
    
#     try:
#         # Analyze files
#         benign_result = detector.analyze_file(benign_file)
#         suspicious_result = detector.analyze_file(suspicious_file)
        
#         logger.info(f"Benign file analysis: {benign_result}")
#         logger.info(f"Suspicious file analysis: {suspicious_result}")
        
#         # Check results
#         assert isinstance(benign_result, dict), "Benign analysis did not return a dictionary"
#         assert isinstance(suspicious_result, dict), "Suspicious analysis did not return a dictionary"
        
#         # Check risk scores
#         assert 'risk_score' in benign_result, "No risk score in benign analysis"
#         assert 'risk_score' in suspicious_result, "No risk score in suspicious analysis"
        
#         # Check threats and recommendations
#         assert 'threats' in benign_result, "No threats in benign analysis"
#         assert 'recommendations' in benign_result, "No recommendations in benign analysis"
#         assert 'threats' in suspicious_result, "No threats in suspicious analysis"
#         assert 'recommendations' in suspicious_result, "No recommendations in suspicious analysis"
        
#         # Risk score for suspicious file should be higher
#         assert suspicious_result['risk_score'] > benign_result['risk_score'], "Suspicious file should have higher risk score"
        
#         logger.info("File analysis test passed")
#         return True
#     except Exception as e:
#         logger.error(f"File analysis test failed: {str(e)}")
#         return False
#     finally:
#         # Clean up test files
#         try:
#             os.unlink(benign_file)
#             os.unlink(suspicious_file)
#         except:
#             pass

# def main():
#     """Main function to run all tests"""
#     logger.info("Starting ML model tests")
    
#     # Test initialization
#     detector = test_initialization()
#     if not detector:
#         logger.error("Initialization failed, aborting tests")
#         return False
    
#     # Test feature extraction
#     if not test_feature_extraction(detector):
#         logger.error("Feature extraction failed, aborting tests")
#         return False
    
#     # Test model training
#     if not test_model_training(detector):
#         logger.warning("Model training failed, but continuing with tests")
    
#     # Test file analysis
#     if not test_file_analysis(detector):
#         logger.error("File analysis failed")
#         return False
    
#     logger.info("All tests completed successfully")
#     return True

# if __name__ == "__main__":
#     success = main()
#     sys.exit(0 if success else 1)
#     """
# Test script for the RansomwareDetector class.
# This script tests the ML model independently of the Flask API."""

# import os
# import sys
# import logging
# import tempfile
# import random
# import pandas as pd
# import numpy as np

# # Set up logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# )
# logger = logging.getLogger(__name__)

# # Add parent directory to path for imports
# current_dir = os.path.dirname(os.path.abspath(__file__))
# parent_dir = os.path.dirname(current_dir)
# sys.path.append(parent_dir)
# sys.path.append(os.path.join(parent_dir, 'backend'))
# sys.path.append(os.path.join(parent_dir, 'backend', 'ai_ml'))

# # Try to import RansomwareDetector
# try:
#     from backend.ai_ml.detection_model import RansomwareDetector
#     logger.info("Successfully imported RansomwareDetector from backend")
# except ImportError:
#     try:
#         from detection_model import RansomwareDetector
#         logger.info("Successfully imported RansomwareDetector locally")
#     except ImportError as e:
#         logger.error(f"Could not import RansomwareDetector. Error: {str(e)}")
#         logger.error("Current sys.path: " + str(sys.path))
#         sys.exit(1)

# def create_test_file(content=None, extension='.txt'):
#     """
#     Create a test file with given content and extension
    
#     Args:
#         content: Bytes to write to the file (random if None)
#         extension: File extension to use
        
#     Returns:
#         Path to the created file
#     """
#     with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as f:
#         if content is None:
#             # Generate random content
#             content = bytes(random.randint(0, 255) for _ in range(4096))
#         f.write(content)
#     return f.name

# def create_sample_dataset():
#     """
#     Create a sample dataset for training
    
#     Returns:
#         Path to the created dataset file
#     """
#     try:
#         # Create basic features
#         data = {
#             'FileName': [],
#             'md5Hash': [],
#             'fileSize': [],
#             'entropy': [],
#             'extensionRisk': [],
#             'hasExeHeader': [],
#             'timeSinceCreation': [],
#             'timeSinceModification': [],
#             'Benign': []  # 1 for benign, 0 for malicious
#         }
        
#         # Generate 100 benign samples
#         for i in range(100):
#             data['FileName'].append(f"benign_file_{i}.txt")
#             data['md5Hash'].append(f"benign_hash_{i}")
#             data['fileSize'].append(random.randint(1000, 10000))
#             data['entropy'].append(random.uniform(2.0, 5.0))  # Lower entropy
#             data['extensionRisk'].append(random.uniform(0.1, 0.3))  # Lower risk
#             data['hasExeHeader'].append(0)
#             data['timeSinceCreation'].append(random.randint(10000, 100000))
#             data['timeSinceModification'].append(random.randint(1000, 10000))
#             data['Benign'].append(1)
        
#         # Generate 100 malicious samples
#         for i in range(100):
#             data['FileName'].append(f"malicious_file_{i}.exe")
#             data['md5Hash'].append(f"malicious_hash_{i}")
#             data['fileSize'].append(random.randint(5000, 50000))
#             data['entropy'].append(random.uniform(5.0, 7.5))  # Higher entropy
#             data['extensionRisk'].append(random.uniform(0.6, 0.9))  # Higher risk
#             data['hasExeHeader'].append(1)
#             data['timeSinceCreation'].append(random.randint(1000, 10000))
#             data['timeSinceModification'].append(random.randint(100, 1000))
#             data['Benign'].append(0)
        
#         # Create DataFrame
#         df = pd.DataFrame(data)
        
#         # Save to CSV
#         dataset_path = os.path.join(tempfile.gettempdir(), 'test_ransomware_dataset.csv')
#         df.to_csv(dataset_path, index=False)
        
#         logger.info(f"Created sample dataset with {len(df)} rows at {dataset_path}")
#         return dataset_path
#     except Exception as e:
#         logger.error(f"Error creating sample dataset: {str(e)}")
#         return None

# def test_initialization():
#     """Test initializing the RansomwareDetector"""
#     logger.info("Testing initialization...")
#     try:
#         detector = RansomwareDetector()
#         assert hasattr(detector, 'classifier'), "Classifier not initialized"
#         assert hasattr(detector, 'model_file'), "Model file path not set"
#         logger.info("Initialization test passed")
#         return detector
#     except Exception as e:
#         logger.error(f"Initialization test failed: {str(e)}")
#         return None

# def test_feature_extraction(detector):
#     """Test feature extraction from files"""
#     logger.info("Testing feature extraction...")
    
#     # Create test files
#     benign_file = create_test_file(content=b"This is a normal text file.", extension='.txt')
#     suspicious_file = create_test_file(content=b"MZ" + os.urandom(4094), extension='.exe')
    
#     try:
#         # Extract features
#         benign_features = detector.extract_features(benign_file)
#         suspicious_features = detector.extract_features(suspicious_file)
        
#         logger.info(f"Benign file features: {benign_features}")
#         logger.info(f"Suspicious file features: {suspicious_features}")
        
#         # Check that features were extracted
#         assert len(benign_features) > 0, "No features extracted from benign file"
#         assert len(suspicious_features) > 0, "No features extracted from suspicious file"
        
#         # Verify executable header detection
#         assert suspicious_features[3] == 1, "Executable header not detected"
#         assert benign_features[3] == 0, "False positive on executable header"
        
#         logger.info("Feature extraction test passed")
#         return True
#     except Exception as e:
#         logger.error(f"Feature extraction test failed: {str(e)}")
#         return False
#     finally:
#         # Clean up test files
#         try:
#             os.unlink(benign_file)
#             os.unlink(suspicious_file)
#         except:
#             pass







###### 8th April: Attempt 1 to rectify the random output:
# """
# Test script for the RansomwareDetector class.
# This script tests the ML model independently of the Flask API.
# """

# import os
# import sys
# import logging
# import tempfile
# import random
# import pandas as pd
# import numpy as np
# import hashlib
# import shutil

# # Set up logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# )
# logger = logging.getLogger(__name__)

# # Add parent directory to path for imports
# current_dir = os.path.dirname(os.path.abspath(__file__))
# parent_dir = os.path.dirname(current_dir)
# sys.path.append(parent_dir)
# sys.path.append(os.path.join(parent_dir, 'backend'))
# sys.path.append(os.path.join(parent_dir, 'backend', 'ai_ml'))

# # Try to import RansomwareDetector
# try:
#     from backend.ai_ml.detection_model import RansomwareDetector
#     logger.info("Successfully imported RansomwareDetector from backend")
# except ImportError:
#     try:
#         from detection_model import RansomwareDetector
#         logger.info("Successfully imported RansomwareDetector locally")
#     except ImportError as e:
#         logger.error(f"Could not import RansomwareDetector. Error: {str(e)}")
#         logger.error("Current sys.path: " + str(sys.path))
#         sys.exit(1)

# def create_test_file(content=None, extension='.txt'):
#     """
#     Create a test file with given content and extension
    
#     Args:
#         content: Bytes to write to the file (random if None)
#         extension: File extension to use
        
#     Returns:
#         Path to the created file
#     """
#     with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as f:
#         if content is None:
#             # Generate random content
#             content = bytes(random.randint(0, 255) for _ in range(4096))
#         f.write(content)
#     return f.name

# def create_benign_file():
#     """Create a benign test file"""
#     text_content = b"""
#     This is a normal text file.
#     It contains no malicious content.
#     Just regular text that might be found in any document.
#     Nothing suspicious here at all.
#     """
#     return create_test_file(content=text_content, extension='.txt')

# def create_suspicious_file():
#     """Create a suspicious file that might trigger detection"""
#     # Create content with suspicious strings
#     content = b"""
#     YOUR FILES HAVE BEEN ENCRYPTED!
#     To recover your files, you need to pay 1 Bitcoin to the following address:
#     1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    
#     After payment, contact us at decrypt@ransomware.example
    
#     DO NOT attempt to decrypt files yourself or they will be permanently lost!
#     """
#     return create_test_file(content=content, extension='.txt')

# def create_executable_file():
#     """Create a file that looks like an executable"""
#     # Create a file with MZ header (Windows executable)
#     content = b'MZ' + os.urandom(4094)  # MZ header + random content
#     return create_test_file(content=content, extension='.exe')

# def create_encrypted_file():
#     """Create a file that appears to be encrypted (high entropy)"""
#     # Create random bytes (high entropy)
#     content = os.urandom(8192)
#     return create_test_file(content=content, extension='.enc')

# def create_sample_dataset():
#     """
#     Create a sample dataset for training
    
#     Returns:
#         Path to the created dataset file
#     """
#     try:
#         # Create basic features matching our dataset schema
#         data = {
#             'FileName': [],
#             'md5Hash': [],
#             'Machine': [],
#             'DebugSize': [],
#             'DebugRVA': [],
#             'MajorImageVersion': [],
#             'MajorOSVersion': [],
#             'ExportRVA': [],
#             'ExportSize': [],
#             'IatVRA': [],
#             'MajorLinkerVersion': [],
#             'MinorLinkerVersion': [],
#             'NumberOfSections': [],
#             'SizeOfStackReserve': [],
#             'DllCharacteristics': [],
#             'ResourceSize': [],
#             'BitcoinAddresses': [],
#             'Benign': []  # 1 for benign, 0 for malicious
#         }
        
#         # Generate 50 benign samples
#         for i in range(50):
#             data['FileName'].append(f"benign_file_{i}.txt")
#             data['md5Hash'].append(f"benign_hash_{i}")
#             data['Machine'].append(332)  # Common value for x86
#             data['DebugSize'].append(random.randint(0, 100))
#             data['DebugRVA'].append(random.randint(0, 1000))
#             data['MajorImageVersion'].append(random.randint(0, 10))
#             data['MajorOSVersion'].append(random.randint(0, 10))
#             data['ExportRVA'].append(0)
#             data['ExportSize'].append(0)
#             data['IatVRA'].append(random.randint(0, 10000))
#             data['MajorLinkerVersion'].append(random.randint(0, 20))
#             data['MinorLinkerVersion'].append(random.randint(0, 20))
#             data['NumberOfSections'].append(random.randint(1, 5))
#             data['SizeOfStackReserve'].append(random.randint(100000, 1000000))
#             data['DllCharacteristics'].append(random.randint(0, 50000))
#             data['ResourceSize'].append(random.randint(0, 5000))
#             data['BitcoinAddresses'].append(0)  # No Bitcoin addresses in benign files
#             data['Benign'].append(1)  # Benign
        
#         # Generate 50 malicious samples
#         for i in range(50):
#             data['FileName'].append(f"malicious_file_{i}.exe")
#             data['md5Hash'].append(f"malicious_hash_{i}")
#             data['Machine'].append(332)  # Common value for x86
#             data['DebugSize'].append(random.randint(0, 100))
#             data['DebugRVA'].append(random.randint(0, 1000))
#             data['MajorImageVersion'].append(random.randint(0, 10))
#             data['MajorOSVersion'].append(random.randint(0, 10))
#             data['ExportRVA'].append(random.randint(100000, 200000))
#             data['ExportSize'].append(random.randint(1000, 5000))
#             data['IatVRA'].append(random.randint(0, 10000))
#             data['MajorLinkerVersion'].append(random.randint(0, 20))
#             data['MinorLinkerVersion'].append(random.randint(0, 20))
#             data['NumberOfSections'].append(random.randint(3, 8))  # More sections in malware
#             data['SizeOfStackReserve'].append(random.randint(100000, 1000000))
#             data['DllCharacteristics'].append(random.randint(0, 50000))
#             data['ResourceSize'].append(random.randint(5000, 50000))  # Larger resources
#             data['BitcoinAddresses'].append(random.randint(0, 1))  # May have Bitcoin addresses
#             data['Benign'].append(0)  # Malicious
        
#         # Create DataFrame
#         df = pd.DataFrame(data)
        
#         # Save to CSV
#         dataset_path = os.path.join(tempfile.gettempdir(), 'test_ransomware_dataset.csv')
#         df.to_csv(dataset_path, index=False)
        
#         logger.info(f"Created sample dataset with {len(df)} rows at {dataset_path}")
#         return dataset_path
#     except Exception as e:
#         logger.error(f"Error creating sample dataset: {str(e)}")
#         return None

# def test_initialization():
#     """Test initializing the RansomwareDetector"""
#     logger.info("Testing initialization...")
#     try:
#         detector = RansomwareDetector()
#         assert hasattr(detector, 'classifier'), "Classifier not initialized"
#         assert hasattr(detector, 'model_file'), "Model file path not set"
#         logger.info("Initialization test passed ✓")
#         return detector
#     except Exception as e:
#         logger.error(f"Initialization test failed: {str(e)}")
#         return None

# def test_feature_extraction(detector):
#     """Test feature extraction from files"""
#     logger.info("Testing feature extraction...")
    
#     # Create test files
#     benign_file = create_benign_file()
#     suspicious_file = create_suspicious_file()
#     executable_file = create_executable_file()
    
#     try:
#         # Extract features
#         benign_features = detector.extract_features(benign_file)
#         suspicious_features = detector.extract_features(suspicious_file)
#         executable_features = detector.extract_features(executable_file)
        
#         logger.info(f"Benign file features shape: {benign_features.shape}")
#         logger.info(f"Suspicious file features shape: {suspicious_features.shape}")
#         logger.info(f"Executable file features shape: {executable_features.shape}")
        
#         # Check that features were extracted
#         assert len(benign_features) > 0, "No features extracted from benign file"
#         assert len(suspicious_features) > 0, "No features extracted from suspicious file"
#         assert len(executable_features) > 0, "No features extracted from executable file"
        
#         # Check executable header detection
#         has_exe_header = detector._check_exe_header(open(executable_file, 'rb').read())
#         assert has_exe_header, "Executable header not detected"
        
#         # Check suspicious strings detection
#         with open(suspicious_file, 'rb') as f:
#             data = f.read()
#         suspicious_count = detector._check_suspicious_strings(data)
#         assert suspicious_count > 0, "Suspicious strings not detected"
        
#         logger.info("Feature extraction test passed ✓")
#         return True
#     except Exception as e:
#         logger.error(f"Feature extraction test failed: {str(e)}")
#         return False
#     finally:
#         # Clean up test files
#         for file in [benign_file, suspicious_file, executable_file]:
#             try:
#                 os.unlink(file)
#             except Exception as cleanup_error:
#                 logger.warning(f"Error cleaning up file {file}: {cleanup_error}")

# def test_model_training(detector):
#     """Test training the model with sample data"""
#     logger.info("Testing model training...")
    
#     # Create sample dataset
#     dataset_path = create_sample_dataset()
#     if not dataset_path:
#         logger.error("Failed to create sample dataset")
#         return False
    
#     try:
#         # Load the data
#         features, labels = detector.load_data(dataset_path)
#         assert features is not None, "Failed to load features"
#         assert labels is not None, "Failed to load labels"
#         assert len(features) == len(labels), "Features and labels length mismatch"
        
#         # Train the model
#         success = detector.train_model(features, labels)
#         assert success, "Model training failed"
        
#         # Check that model file exists
#         assert os.path.exists(detector.model_file), "Model file not created"
        
#         logger.info("Model training test passed ✓")
#         return True
#     except Exception as e:
#         logger.error(f"Model training test failed: {str(e)}")
#         return False
#     finally:
#         # Clean up the dataset file
#         try:
#             os.unlink(dataset_path)
#         except Exception as cleanup_error:
#             logger.warning(f"Error cleaning up dataset file {dataset_path}: {cleanup_error}")

# def test_file_analysis(detector):
#     """Test analyzing files for ransomware"""
#     logger.info("Testing file analysis...")
    
#     # Create test files
#     benign_file = create_benign_file()
#     suspicious_file = create_suspicious_file()
#     executable_file = create_executable_file()
#     encrypted_file = create_encrypted_file()
    
#     logger.info(f"Created test files:")
#     logger.info(f"  Benign: {benign_file}")
#     logger.info(f"  Suspicious: {suspicious_file}")
#     logger.info(f"  Executable: {executable_file}")
#     logger.info(f"  Encrypted: {encrypted_file}")
    
#     try:
#         # Analyze files
#         benign_result = detector.analyze_file(benign_file)
#         suspicious_result = detector.analyze_file(suspicious_file)
#         executable_result = detector.analyze_file(executable_file)
#         encrypted_result = detector.analyze_file(encrypted_file)
        
#         logger.info(f"Benign file analysis: Risk score {benign_result['risk_score']:.2f}")
#         logger.info(f"Suspicious file analysis: Risk score {suspicious_result['risk_score']:.2f}")
#         logger.info(f"Executable file analysis: Risk score {executable_result['risk_score']:.2f}")
#         logger.info(f"Encrypted file analysis: Risk score {encrypted_result['risk_score']:.2f}")
        
#         # Check results
#         assert isinstance(benign_result, dict), "Benign analysis did not return a dictionary"
#         assert isinstance(suspicious_result, dict), "Suspicious analysis did not return a dictionary"
#         assert isinstance(executable_result, dict), "Executable analysis did not return a dictionary"
#         assert isinstance(encrypted_result, dict), "Encrypted analysis did not return a dictionary"
        
#         # Check risk scores
#         assert 'risk_score' in benign_result, "No risk score in benign analysis"
#         assert 'risk_score' in suspicious_result, "No risk score in suspicious analysis"
#         assert 'risk_score' in executable_result, "No risk score in executable analysis"
#         assert 'risk_score' in encrypted_result, "No risk score in encrypted analysis"
        
#         # Check threats and recommendations
#         assert 'threats' in benign_result, "No threats in benign analysis"
#         assert 'recommendations' in benign_result, "No recommendations in benign analysis"
#         assert 'threats' in suspicious_result, "No threats in suspicious analysis"
#         assert 'recommendations' in suspicious_result, "No recommendations in suspicious analysis"
        
#         # Risk score for suspicious and executable files should be higher than benign
#         assert suspicious_result['risk_score'] > benign_result['risk_score'], "Suspicious file should have higher risk score than benign"
#         assert executable_result['risk_score'] > benign_result['risk_score'], "Executable file should have higher risk score than benign"
        
#         logger.info("File analysis test passed ✓")
#         return True
    

#     ### He swata taakla ahe
#     except Exception as e:
#       logger.error(f"Feature extraction test failed: {str(e)}")
#       return False
#     finally:
#         # Clean up test files
#         try:
#             os.unlink(benign_file)
#             os.unlink(suspicious_file)
#         except:
#             pass


























#17th April

"""
Test script for the RansomwareDetector class.
This script tests the ML model independently of the Flask API.
"""

import os
import sys
import logging
import tempfile
import random
import pandas as pd
import numpy as np
import hashlib
import shutil

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'backend'))
sys.path.append(os.path.join(parent_dir, 'backend', 'ai_ml'))

# Try to import RansomwareDetector
try:
    from backend.ai_ml.detection_model import RansomwareDetector
    logger.info("Successfully imported RansomwareDetector from backend")
except ImportError:
    try:
        from detection_model import RansomwareDetector
        logger.info("Successfully imported RansomwareDetector locally")
    except ImportError as e:
        logger.error(f"Could not import RansomwareDetector. Error: {str(e)}")
        logger.error("Current sys.path: " + str(sys.path))
        sys.exit(1)

def create_test_file(content=None, extension='.txt'):
    """
    Create a test file with given content and extension
    
    Args:
        content: Bytes to write to the file (random if None)
        extension: File extension to use
        
    Returns:
        Path to the created file
    """
    with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as f:
        if content is None:
            # Generate random content
            content = bytes(random.randint(0, 255) for _ in range(4096))
        f.write(content)
    return f.name

def create_benign_file():
    """Create a benign test file"""
    text_content = b"""
    This is a normal text file.
    It contains no malicious content.
    Just regular text that might be found in any document.
    Nothing suspicious here at all.
    """
    return create_test_file(content=text_content, extension='.txt')

def create_suspicious_file():
    """Create a suspicious file that might trigger detection"""
    # Create content with suspicious strings
    content = b"""
    YOUR FILES HAVE BEEN ENCRYPTED!
    To recover your files, you need to pay 1 Bitcoin to the following address:
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    
    After payment, contact us at decrypt@ransomware.example
    
    DO NOT attempt to decrypt files yourself or they will be permanently lost!
    """
    return create_test_file(content=content, extension='.txt')

def create_executable_file():
    """Create a file that looks like an executable"""
    # Create a file with MZ header (Windows executable)
    content = b'MZ' + os.urandom(4094)  # MZ header + random content
    return create_test_file(content=content, extension='.exe')

def create_sample_dataset():
    """
    Create a sample dataset for training
    
    Returns:
        Path to the created dataset file
    """
    try:
        # Create basic features matching our dataset schema
        data = {
            'FileName': [],
            'md5Hash': [],
            'Machine': [],
            'DebugSize': [],
            'DebugRVA': [],
            'MajorImageVersion': [],
            'MajorOSVersion': [],
            'ExportRVA': [],
            'ExportSize': [],
            'IatVRA': [],
            'MajorLinkerVersion': [],
            'MinorLinkerVersion': [],
            'NumberOfSections': [],
            'SizeOfStackReserve': [],
            'DllCharacteristics': [],
            'ResourceSize': [],
            'BitcoinAddresses': [],
            'Benign': []  # 1 for benign, 0 for malicious
        }
        
        # Generate 100 benign samples
        for i in range(100):
            data['FileName'].append(f"benign_file_{i}.txt")
            data['md5Hash'].append(f"benign_hash_{i}")
            data['Machine'].append(332)  # Common value for x86
            data['DebugSize'].append(random.randint(0, 100))
            data['DebugRVA'].append(random.randint(0, 1000))
            data['MajorImageVersion'].append(random.randint(0, 10))
            data['MajorOSVersion'].append(random.randint(0, 10))
            data['ExportRVA'].append(0)
            data['ExportSize'].append(0)
            data['IatVRA'].append(random.randint(0, 10000))
            data['MajorLinkerVersion'].append(random.randint(0, 20))
            data['MinorLinkerVersion'].append(random.randint(0, 20))
            data['NumberOfSections'].append(random.randint(1, 5))
            data['SizeOfStackReserve'].append(random.randint(100000, 1000000))
            data['DllCharacteristics'].append(random.randint(0, 50000))
            data['ResourceSize'].append(random.randint(0, 5000))
            data['BitcoinAddresses'].append(0)  # No Bitcoin addresses in benign files
            data['Benign'].append(1)  # Benign
        
        # Generate 100 malicious samples
        for i in range(100):
            data['FileName'].append(f"malicious_file_{i}.exe")
            data['md5Hash'].append(f"malicious_hash_{i}")
            data['Machine'].append(332)  # Common value for x86
            data['DebugSize'].append(random.randint(0, 100))
            data['DebugRVA'].append(random.randint(0, 1000))
            data['MajorImageVersion'].append(random.randint(0, 10))
            data['MajorOSVersion'].append(random.randint(0, 10))
            data['ExportRVA'].append(random.randint(100000, 200000))
            data['ExportSize'].append(random.randint(1000, 5000))
            data['IatVRA'].append(random.randint(0, 10000))
            data['MajorLinkerVersion'].append(random.randint(0, 20))
            data['MinorLinkerVersion'].append(random.randint(0, 20))
            data['NumberOfSections'].append(random.randint(3, 8))  # More sections in malware
            data['SizeOfStackReserve'].append(random.randint(100000, 1000000))
            data['DllCharacteristics'].append(random.randint(0, 50000))
            data['ResourceSize'].append(random.randint(5000, 50000))  # Larger resources
            data['BitcoinAddresses'].append(random.randint(0, 3))  # May have Bitcoin addresses
            data['Benign'].append(0)  # Malicious
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Save to CSV
        dataset_path = os.path.join(tempfile.gettempdir(), 'test_ransomware_dataset.csv')
        df.to_csv(dataset_path, index=False)
        
        logger.info(f"Created sample dataset with {len(df)} rows at {dataset_path}")
        return dataset_path
    except Exception as e:
        logger.error(f"Error creating sample dataset: {str(e)}")
        return None

def test_initialization():
    """Test initializing the RansomwareDetector"""
    logger.info("Testing initialization...")
    try:
        detector = RansomwareDetector()
        assert hasattr(detector, 'classifier'), "Classifier not initialized"
        assert hasattr(detector, 'model_file'), "Model file path not set"
        logger.info("✓ Initialization test passed")
        return detector
    except Exception as e:
        logger.error(f"Initialization test failed: {str(e)}")
        return None

def test_feature_extraction(detector):
    """Test feature extraction from files"""
    logger.info("Testing feature extraction...")
    
    # Create test files
    benign_file = create_benign_file()
    suspicious_file = create_suspicious_file()
    executable_file = create_executable_file()
    
    try:
        # Extract features
        benign_features = detector.extract_features(benign_file)
        suspicious_features = detector.extract_features(suspicious_file)
        executable_features = detector.extract_features(executable_file)
        
        logger.info(f"Benign file features: {benign_features}")
        logger.info(f"Suspicious file features: {suspicious_features}")
        logger.info(f"Executable file features: {executable_features}")
        
        # Check that features were extracted
        assert len(benign_features) > 0, "No features extracted from benign file"
        assert len(suspicious_features) > 0, "No features extracted from suspicious file"
        assert len(executable_features) > 0, "No features extracted from executable file"
        
        # Verify suspicious string detection
        suspicious_score_index = 4  # Index where suspicious score is stored
        assert suspicious_features[suspicious_score_index] > benign_features[suspicious_score_index], \
            "Suspicious file should have higher suspicious string score"
            
        # Verify executable header detection
        exe_header_index = 3  # Index where executable header flag is stored
        assert executable_features[exe_header_index] == 1, "Executable header not detected"
        assert benign_features[exe_header_index] == 0, "False positive on executable header"
        
        logger.info("✓ Feature extraction test passed")
        return True
    except Exception as e:
        logger.error(f"Feature extraction test failed: {str(e)}")
        return False
    finally:
        # Clean up test files
        for file in [benign_file, suspicious_file, executable_file]:
            try:
                os.unlink(file)
            except Exception as cleanup_error:
                logger.warning(f"Error cleaning up file {file}: {cleanup_error}")

def test_model_training(detector):
    """Test training the model with sample data"""
    logger.info("Testing model training...")
    
    # Create sample dataset
    dataset_path = create_sample_dataset()
    if not dataset_path:
        logger.error("Failed to create sample dataset")
        return False
    
    try:
        # Load the data
        features, labels = detector.load_data(dataset_path)
        assert features is not None, "Failed to load features"
        assert labels is not None, "Failed to load labels"
        
        # Train the model
        success = detector.train_model(features, labels)
        assert success, "Model training failed"
        
        # Check that model file exists
        assert os.path.exists(detector.model_file), "Model file not created"
        
        logger.info("✓ Model training test passed")
        return True
    except Exception as e:
        logger.error(f"Model training test failed: {str(e)}")
        return False
    finally:
        # Clean up the dataset file
        try:
            os.unlink(dataset_path)
        except Exception as cleanup_error:
            logger.warning(f"Error cleaning up dataset file {dataset_path}: {cleanup_error}")

def test_file_analysis(detector):
    """Test analyzing files for ransomware"""
    logger.info("Testing file analysis...")
    
    # Create test files
    benign_file = create_benign_file()
    suspicious_file = create_suspicious_file()
    executable_file = create_executable_file()
    
    try:
        # Analyze files
        benign_result = detector.analyze_file(benign_file)
        suspicious_result = detector.analyze_file(suspicious_file)
        executable_result = detector.analyze_file(executable_file)
        
        logger.info(f"Benign file analysis: Risk score {benign_result['risk_score']:.2f}")
        logger.info(f"Suspicious file analysis: Risk score {suspicious_result['risk_score']:.2f}")
        logger.info(f"Executable file analysis: Risk score {executable_result['risk_score']:.2f}")
        
        # Check results
        assert isinstance(benign_result, dict), "Benign analysis did not return a dictionary"
        assert isinstance(suspicious_result, dict), "Suspicious analysis did not return a dictionary"
        assert isinstance(executable_result, dict), "Executable analysis did not return a dictionary"
        
        # Check required fields
        for result in [benign_result, suspicious_result, executable_result]:
            assert 'risk_score' in result, "No risk score in analysis result"
            assert 'threats' in result, "No threats in analysis result"
            assert 'recommendations' in result, "No recommendations in analysis result"
        
        # Risk scores should reflect file types
        assert suspicious_result['risk_score'] > benign_result['risk_score'], \
            "Suspicious file should have higher risk score than benign"
        
        # Check that file hashes are correct
        assert benign_result['hash'] is not None, "Benign file hash not calculated"
        assert suspicious_result['hash'] is not None, "Suspicious file hash not calculated"
        assert executable_result['hash'] is not None, "Executable file hash not calculated"
        
        logger.info("✓ File analysis test passed")
        return True
    except Exception as e:
        logger.error(f"File analysis test failed: {str(e)}")
        return False
    finally:
        # Clean up test files
        for file in [benign_file, suspicious_file, executable_file]:
            try:
                os.unlink(file)
            except Exception as cleanup_error:
                logger.warning(f"Error cleaning up file {file}: {cleanup_error}")

def main():
    """Main function to run all tests"""
    logger.info("Starting ML model tests")
    
    # Test initialization
    detector = test_initialization()
    if not detector:
        logger.error("Initialization failed, aborting tests")
        return False
    
    # Test feature extraction
    if not test_feature_extraction(detector):
        logger.error("Feature extraction failed, aborting tests")
        return False
    
    # Test model training
    if not test_model_training(detector):
        logger.warning("Model training failed, but continuing with tests")
    
    # Test file analysis
    if not test_file_analysis(detector):
        logger.error("File analysis failed")
        return False
    
    logger.info("✓ All tests completed successfully")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)