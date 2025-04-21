##17th April
"""
Flask API for Ransomware Detection System.
Provides endpoints for file analysis and reporting.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import logging
import tempfile
import shutil
import json
from datetime import datetime

# Import the detection model
try:
    from backend.ai_ml.enhanced_detection_model import EnhancedRansomwareDetector as RansomwareDetector
except ImportError:
    # Try local import if backend module not found
    try:
        from detection_model import RansomwareDetector
    except ImportError:
        print("Error: Cannot import RansomwareDetector. Ensure the file exists in the correct location.")
        import sys
        sys.exit(1)

# Initialize Flask app
app = Flask(__name__, static_folder='frontend')
CORS(app)  # Enable CORS for all routes and origins

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("flask_api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {
    # Executable and scripts
    'exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 
    # Archives
    'zip', 'rar', '7z', 
    # Documents
    'docx', 'xlsx', 'pptx', 'pdf', 'doc', 'xls', 'ppt', 'txt',
    # Other
    'crypt', 'crypted', 'encrypted', 'enc', 'locked'
}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize the ransomware detector
detector = RansomwareDetector()

def allowed_file(filename):
    """
    Check if the file has an allowed extension
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Root endpoint (serve frontend)
@app.route('/')
def index():
    """Serve the frontend index.html"""
    return app.send_static_file('index.html')

# Serve static files
@app.route('/<path:path>')
def static_files(path):
    """Serve static files from the frontend directory"""
    return app.send_static_file(path)

# API Health Check
@app.route('/api/status')
def api_status():
    """API health check endpoint"""
    model_loaded = hasattr(detector, 'classifier') and detector.classifier is not None
    
    return jsonify({
        "status": "online",
        "model_loaded": model_loaded,
        "time": datetime.now().isoformat()
    })

# File Analysis Endpoint
@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    """
    Analyze a file for ransomware characteristics
    
    Expects:
        - File in multipart/form-data
        
    Returns:
        - JSON with analysis results
    """
    try:
        logger.info("Received file analysis request")
        
        # Check if file is present in request
        if 'file' not in request.files:
            logger.warning("No file part in the request")
            return jsonify({
                "status": "error",
                "message": "No file part in the request"
            }), 400
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            logger.warning("No file selected")
            return jsonify({
                "status": "error",
                "message": "No file selected"
            }), 400
            
        # Create a temporary directory for the file
        temp_dir = tempfile.mkdtemp()
        try:
            # Securely save the file
            filename = secure_filename(file.filename)
            filepath = os.path.join(temp_dir, filename)
            file.save(filepath)
            
            logger.info(f"File saved temporarily at {filepath}")
            
            # Analyze the file
            analysis_result = detector.analyze_file(filepath)
            
            # Add file information
            analysis_result['filename'] = filename
            analysis_result['analysis_time'] = datetime.now().isoformat()
            
            logger.info(f"Analysis complete: risk_score={analysis_result['risk_score']}")
            
            return jsonify({
                "status": "success",
                "data": analysis_result
            })
            
        except Exception as e:
            logger.error(f"Error during file processing: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Error processing file: {str(e)}"
            }), 500
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Removed temporary directory {temp_dir}")
            except Exception as e:
                logger.error(f"Error cleaning up temp directory: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error during file analysis: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error analyzing file: {str(e)}"
        }), 500

# Incident Reporting Endpoint
@app.route('/api/incident', methods=['POST'])
def report_incident():
    """
    Report a security incident
    
    Expects:
        - JSON with incident details
        
    Returns:
        - JSON with incident ID and status
    """
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['description', 'severity', 'affectedSystems']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "status": "error",
                    "message": f"Missing required field: {field}"
                }), 400
                
        # Log the incident
        incident = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "description": data['description'],
            "severity": data['severity'],
            "affectedSystems": data['affectedSystems'],
            "timestamp": datetime.now().isoformat(),
            "status": "open"
        }
        
        logger.info(f"Incident reported: {json.dumps(incident)}")
        
        # In a real implementation, you would save this to a database
        # For now, save to a file
        incidents_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'incidents.json')
        
        # Load existing incidents
        incidents = []
        if os.path.exists(incidents_file):
            try:
                with open(incidents_file, 'r') as f:
                    incidents = json.load(f)
            except json.JSONDecodeError:
                incidents = []
                
        # Add new incident
        incidents.append(incident)
        
        # Save incidents
        with open(incidents_file, 'w') as f:
            json.dump(incidents, f, indent=2)
            
        return jsonify({
            "status": "success",
            "incident_id": incident['id'],
            "message": "Incident reported successfully"
        })
        
    except Exception as e:
        logger.error(f"Error reporting incident: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error reporting incident: {str(e)}"
        }), 500

# Security Metrics
@app.route('/api/security-metrics', methods=['GET'])
def get_security_metrics():
    """
    Get security metrics for dashboard
    
    Returns:
        - JSON with security metrics
    """
    try:
        # In a real system, we would fetch this data from a database
        # For now, we'll generate mock data for demonstration
        
        # Generate metrics for the last 24 hours
        current_date = datetime.now()
        metrics = []
        
        for i in range(24):
            timestamp = current_date.replace(hour=current_date.hour - i)
            
            # Generate reasonable but slightly randomized metrics
            metrics.append({
                "timestamp": timestamp.isoformat(),
                "cpuUsage": 20 + (i % 5) * 3,  # Range: 20-35%
                "memoryUsage": 40 + (i % 6) * 2,  # Range: 40-50%
                "diskUsage": 55 + (i % 4),  # Range: 55-59%
                "networkActivity": 5000 + (i % 10) * 1000  # Range: 5000-15000 bytes
            })
        
        # Check for recent incidents to create alerts
        incidents_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'incidents.json')
        recent_alerts = []
        
        if os.path.exists(incidents_file):
            try:
                with open(incidents_file, 'r') as f:
                    incidents = json.load(f)
                    
                # Convert recent incidents to alerts
                for incident in incidents[-3:]:  # Get last 3 incidents
                    recent_alerts.append({
                        "id": incident.get('id', ''),
                        "type": "Incident Report",
                        "severity": incident.get('severity', 'medium'),
                        "message": incident.get('description', 'Unknown incident'),
                        "timestamp": incident.get('timestamp', datetime.now().isoformat())
                    })
            except:
                pass
                
        # If we don't have 3 recent incidents, add some sample alerts
        if len(recent_alerts) < 3:
            sample_alerts = [
                {
                    "id": 1,
                    "type": "Ransomware Detection",
                    "severity": "high",
                    "message": "Potential ransomware detected in file upload",
                    "timestamp": (current_date.replace(hour=current_date.hour - 1)).isoformat()
                },
                {
                    "id": 2, 
                    "type": "Suspicious Activity",
                    "severity": "medium",
                    "message": "Multiple failed login attempts detected",
                    "timestamp": (current_date.replace(hour=current_date.hour - 3)).isoformat()
                },
                {
                    "id": 3,
                    "type": "System Security",
                    "severity": "low",
                    "message": "Software update available",
                    "timestamp": (current_date.replace(hour=current_date.hour - 5)).isoformat()
                }
            ]
            
            # Only add as many as needed
            for i in range(3 - len(recent_alerts)):
                if i < len(sample_alerts):
                    recent_alerts.append(sample_alerts[i])
        
        # Generate threat data
        threat_data = {
            "malwareDetected": 2,
            "suspiciousFiles": 5,
            "blockedAttacks": 8,
            "networkThreats": 3
        }
        
        # Calculate security score (in a real system this would be based on actual data)
        security_score = 85
        
        return jsonify({
            "status": "success",
            "metrics": metrics,
            "alerts": recent_alerts,
            "threatData": threat_data,
            "securityScore": security_score
        })
        
    except Exception as e:
        logger.error(f"Error getting security metrics: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error getting security metrics: {str(e)}"
        }), 500

# Error handling
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500

if __name__ == '__main__':
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Ransomware Detection API')
    parser.add_argument('--test', action='store_true', help='Run tests and exit')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to run the server on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--train', action='store_true', help='Train model before starting')
    
    args = parser.parse_args()
    
    # If --train flag is provided, try to train the model
    if args.train:
        print("Training model...")
        dataset_paths = [
            'ransomware_dataset.csv',
            '../ransomware_dataset.csv',
            '../../ransomware_dataset.csv',
        ]
        
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
    
    # Start the server
    port = int(os.environ.get('PORT', args.port))
    logger.info(f"Starting Flask API on port {port}")
    app.run(host=args.host, port=port, debug=args.debug)
        