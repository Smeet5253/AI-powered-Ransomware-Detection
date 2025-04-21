### Mitigation Attempt 1:  
### Mitigation is working But the risk score is 50% for all the files. This means that the model is not working properly. This is a very serious issue.

"""
Enhanced Flask API for Ransomware Detection and Mitigation System.

This module provides a REST API for file analysis, incident reporting,
quarantine management, and system status monitoring. It integrates with the 
EnhancedRansomwareDetector to analyze files and provide mitigation strategies.
"""

import os
import sys
import logging
import tempfile
import shutil
import json
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import the enhanced detection model
try:
    from enhanced_detection_model import EnhancedRansomwareDetector
    print("Successfully imported EnhancedRansomwareDetector")
except ImportError:
    try:
        from backend.ai_ml.enhanced_detection_model import EnhancedRansomwareDetector
        print("Successfully imported EnhancedRansomwareDetector from backend")
    except ImportError as e:
        print(f"Error importing EnhancedRansomwareDetector: {str(e)}")
        print(f"Current sys.path: {sys.path}")
        sys.exit(1)

# Initialize Flask app
app = Flask(__name__, static_folder='frontend')
CORS(app)  # Enable CORS for all routes and origins

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
QUARANTINE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine')
ALLOWED_EXTENSIONS = {
    # Executable and scripts
    'exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'hta',
    # Archives
    'zip', 'rar', '7z', 'tar', 'gz',
    # Documents
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'txt',
    # Other
    'crypt', 'crypted', 'encrypted', 'enc', 'locked'
}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Ensure required directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Initialize the ransomware detector
detector = EnhancedRansomwareDetector()

# Try to train/load model if dataset exists
dataset_paths = [
    'ransomware_dataset.csv',
    '../ransomware_dataset.csv',
    '../../ransomware_dataset.csv',
]

# Train model if dataset exists and model isn't already loaded
if not hasattr(detector, 'classifier') or detector.classifier is None:
    for dataset_path in dataset_paths:
        if os.path.exists(dataset_path):
            logger.info(f"Found dataset at {dataset_path}, training model...")
            features, labels = detector.load_dataset(dataset_path)
            if features is not None and labels is not None:
                detector.train_model(features, labels)
                break
    if not hasattr(detector, 'classifier') or detector.classifier is None:
        logger.warning("No dataset found or model training failed. Using fallback heuristic detection.")


def allowed_file(filename: str) -> bool:
    """
    Check if the file has an allowed extension
    
    Args:
        filename: Name of the file
        
    Returns:
        Boolean indicating if file extension is allowed
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


##############################################
# API ROUTES
##############################################

# Root endpoint (serve frontend)
@app.route('/')
def index():
    """Serve the frontend index.html"""
    return send_from_directory('frontend', 'index.html')

# Serve static files
@app.route('/<path:path>')
def static_files(path):
    """Serve static files from the frontend directory"""
    return send_from_directory('frontend', path)

#--------------------------------------------
# Status & Health Endpoints
#--------------------------------------------

@app.route('/api/status')
def api_status():
    """
    Get the status of the API and ML model
    
    Returns:
        JSON with API status information
    """
    try:
        # Check if model is loaded
        model_loaded = hasattr(detector, 'classifier') and detector.classifier is not None
        
        # System information
        status_info = {
            "status": "online",
            "service": "Ransomware Detection and Mitigation API",
            "version": detector.VERSION if hasattr(detector, 'VERSION') else "1.0.0",
            "model_loaded": model_loaded,
            "model_path": detector.model_path if model_loaded else None,
            "allowed_file_types": list(ALLOWED_EXTENSIONS),
            "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
            "quarantine_enabled": True,
            "mitigation_enabled": True,
            "time": datetime.now().isoformat()
        }
        
        # Add model details if available
        if model_loaded and hasattr(detector, 'train_stats'):
            status_info["model_stats"] = detector.train_stats
        
        return jsonify(status_info)
    except Exception as e:
        logger.error(f"Error checking API status: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error checking status: {str(e)}"
        }), 500

#--------------------------------------------
# Analysis Endpoints
#--------------------------------------------

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
        
        # Check file size
        if request.content_length and request.content_length > MAX_FILE_SIZE:
            logger.warning(f"File too large: {request.content_length} bytes")
            return jsonify({
                "status": "error",
                "message": f"File exceeds maximum size of {MAX_FILE_SIZE // (1024 * 1024)}MB"
            }), 413
        
        # Create a temporary directory for the file
        temp_dir = tempfile.mkdtemp()
        try:
            # Securely save the file
            filename = secure_filename(file.filename)
            filepath = os.path.join(temp_dir, filename)
            file.save(filepath)
            
            logger.info(f"File saved temporarily at {filepath}")
            
            # Get auto-quarantine preference (default: false)
            auto_quarantine = request.form.get('auto_quarantine', 'false').lower() == 'true'
            
            # Analyze the file
            analysis_result = detector.analyze_file(filepath)
            
            # Log analysis result
            logger.info(f"Analysis complete: risk_score={analysis_result['risk_score']}")
            
            # Check if we should auto-quarantine
            if auto_quarantine and analysis_result['risk_score'] > 0.7:
                quarantine_result = detector.mitigation_handler.quarantine_file(filepath)
                analysis_result['quarantined'] = quarantine_result['success']
                analysis_result['quarantine_info'] = quarantine_result
            else:
                analysis_result['quarantined'] = False
            
            # Return results
            return jsonify({
                "status": "success",
                "data": analysis_result
            })
            
        except Exception as e:
            logger.error(f"Error during file processing: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "status": "error",
                "message": f"Error processing file: {str(e)}"
            }), 500
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Removed temporary directory {temp_dir}")
            except Exception as cleanup_e:
                logger.error(f"Error cleaning up temp directory: {str(cleanup_e)}")
            
    except Exception as e:
        logger.error(f"Error during file analysis: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Error analyzing file: {str(e)}"
        }), 500

#--------------------------------------------
# Mitigation Endpoints
#--------------------------------------------

@app.route('/api/mitigate', methods=['POST'])
def mitigate_file():
    """
    Get mitigation recommendations for a file
    
    Expects:
        - File in multipart/form-data
        
    Returns:
        - JSON with mitigation recommendations
    """
    try:
        # First analyze the file
        analysis_response = analyze_file()
        
        # Check if analysis was successful
        if isinstance(analysis_response, tuple) or analysis_response.status_code != 200:
            # Return the error from analyze_file
            return analysis_response
        
        # Get analysis result
        analysis_data = json.loads(analysis_response.data)
        
        if analysis_data['status'] != 'success':
            return jsonify({
                "status": "error",
                "message": "Analysis failed, cannot generate mitigation recommendations"
            }), 500
        
        # Generate mitigation report
        mitigation_report = detector.mitigation_handler.generate_mitigation_report(
            analysis_data['data']
        )
        
        return jsonify({
            "status": "success",
            "data": {
                "analysis": analysis_data['data'],
                "mitigation_report": mitigation_report
            }
        })
        
    except Exception as e:
        logger.error(f"Error generating mitigation recommendations: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Error generating mitigation recommendations: {str(e)}"
        }), 500

@app.route('/api/quarantine', methods=['POST'])
def quarantine_file():
    """
    Quarantine a file
    
    Expects:
        - File in multipart/form-data
        
    Returns:
        - JSON with quarantine results
    """
    try:
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
            
            # Quarantine the file
            quarantine_result = detector.mitigation_handler.quarantine_file(filepath)
            
            if quarantine_result['success']:
                logger.info(f"File quarantined successfully: {filepath}")
                return jsonify({
                    "status": "success",
                    "data": quarantine_result
                })
            else:
                logger.error(f"Failed to quarantine file: {quarantine_result['message']}")
                return jsonify({
                    "status": "error",
                    "message": quarantine_result['message']
                }), 500
                
        except Exception as e:
            logger.error(f"Error during file quarantine: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Error during file quarantine: {str(e)}"
            }), 500
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Removed temporary directory {temp_dir}")
            except Exception as cleanup_e:
                logger.error(f"Error cleaning up temp directory: {str(cleanup_e)}")
                
    except Exception as e:
        logger.error(f"Error quarantining file: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error quarantining file: {str(e)}"
        }), 500

@app.route('/api/quarantine/list', methods=['GET'])
def list_quarantined_files():
    """
    List all quarantined files
    
    Returns:
        - JSON with list of quarantined files
    """
    try:
        quarantined_files = detector.mitigation_handler.list_quarantined_files()
        
        return jsonify({
            "status": "success",
            "data": {
                "count": len(quarantined_files),
                "files": quarantined_files
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing quarantined files: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error listing quarantined files: {str(e)}"
        }), 500

@app.route('/api/quarantine/<quarantine_id>', methods=['DELETE'])
def delete_from_quarantine(quarantine_id):
    """
    Delete a file from quarantine
    
    Args:
        quarantine_id: Hash of the quarantined file
        
    Returns:
        - JSON with delete results
    """
    try:
        delete_result = detector.mitigation_handler.delete_from_quarantine(quarantine_id)
        
        if delete_result['success']:
            return jsonify({
                "status": "success",
                "data": delete_result
            })
        else:
            return jsonify({
                "status": "error",
                "message": delete_result['message']
            }), 404
            
    except Exception as e:
        logger.error(f"Error deleting file from quarantine: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error deleting file from quarantine: {str(e)}"
        }), 500

@app.route('/api/quarantine/<quarantine_id>/restore', methods=['POST'])
def restore_from_quarantine(quarantine_id):
    """
    Restore a file from quarantine
    
    Args:
        quarantine_id: Hash of the quarantined file
        
    Expects:
        - JSON with restore_path (optional)
        
    Returns:
        - JSON with restore results
    """
    try:
        # Get restore path from request body if provided
        data = request.get_json() or {}
        restore_path = data.get('restore_path')
        
        restore_result = detector.mitigation_handler.restore_from_quarantine(
            quarantine_id=quarantine_id, 
            restore_path=restore_path
        )
        
        if restore_result['success']:
            return jsonify({
                "status": "success",
                "data": restore_result
            })
        else:
            return jsonify({
                "status": "error",
                "message": restore_result['message']
            }), 404
            
    except Exception as e:
        logger.error(f"Error restoring file from quarantine: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error restoring file from quarantine: {str(e)}"
        }), 500

#--------------------------------------------
# Incident Reporting
#--------------------------------------------

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
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['description', 'severity', 'affectedSystems']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "status": "error",
                    "message": f"Missing required field: {field}"
                }), 400
                
        # Validate severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        if data['severity'] not in valid_severities:
            return jsonify({
                "status": "error",
                "message": f"Invalid severity level. Valid options: {', '.join(valid_severities)}"
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
        
        # Save incident to file
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
            
        # Generate mitigation recommendations based on incident
        mitigation_recommendations = []
        
        if data['severity'] == 'critical':
            mitigation_recommendations = [
                "Immediately isolate affected systems from the network",
                "Create forensic backups of affected systems",
                "Engage incident response team",
                "Prepare for potential business continuity procedures"
            ]
        elif data['severity'] == 'high':
            mitigation_recommendations = [
                "Isolate affected systems if possible",
                "Run full system scans on all potentially affected systems",
                "Review logs for suspicious activities",
                "Prepare backups of important data"
            ]
        elif data['severity'] == 'medium':
            mitigation_recommendations = [
                "Run targeted scans on affected systems",
                "Monitor for unusual activities",
                "Verify backup systems are functioning correctly"
            ]
        else:  # low
            mitigation_recommendations = [
                "Monitor systems for unusual behavior",
                "Follow standard security protocols"
            ]
            
        return jsonify({
            "status": "success",
            "data": {
                "incident_id": incident['id'],
                "message": "Incident reported successfully",
                "mitigation_recommendations": mitigation_recommendations
            }
        })
        
    except Exception as e:
        logger.error(f"Error reporting incident: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Error reporting incident: {str(e)}"
        }), 500

#--------------------------------------------
# Dashboard and Analytics
#--------------------------------------------

@app.route('/api/security-metrics', methods=['GET'])
def get_security_metrics():
    """
    Get security metrics for dashboard
    
    Returns:
        - JSON with security metrics
    """
    try:
        # Generate time-based metrics
        current_date = datetime.now()
        metrics = []
        
        # Generate metrics for the last 24 hours
        for i in range(24):
            timestamp = current_date - timedelta(hours=i)
            
            # Create realistic but slightly randomized metrics
            cpu_usage = 20 + (5 * abs((i % 12) - 6))  # Pattern with peak in middle
            memory_usage = 40 + (3 * abs((i % 8) - 4))  # Different pattern
            disk_usage = 55 + (i % 5)  # Slowly increasing
            network_traffic = 5000 + ((i % 6) * 1000)  # Periodic spikes
            
            metrics.append({
                "timestamp": timestamp.isoformat(),
                "cpuUsage": cpu_usage,
                "memoryUsage": memory_usage,
                "diskUsage": disk_usage,
                "networkActivity": network_traffic
            })
        
        # Get incidents for alerts
        incidents_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'incidents.json')
        alerts = []
        
        if os.path.exists(incidents_file):
            try:
                with open(incidents_file, 'r') as f:
                    all_incidents = json.load(f)
                    
                # Convert most recent 5 incidents to alerts
                recent_incidents = sorted(
                    all_incidents, 
                    key=lambda x: x.get('timestamp', ''),
                    reverse=True
                )[:5]
                
                for incident in recent_incidents:
                    alerts.append({
                        "id": incident.get('id', ''),
                        "type": "Incident Report",
                        "severity": incident.get('severity', 'medium'),
                        "message": incident.get('description', 'Unknown incident'),
                        "timestamp": incident.get('timestamp', datetime.now().isoformat())
                    })
            except Exception as e:
                logger.error(f"Error reading incidents file: {str(e)}")
        
        # Get quarantined files
        quarantined_files = detector.mitigation_handler.list_quarantined_files()
        
        # Add quarantined files to alerts
        for qf in quarantined_files[:3]:  # Add up to 3 most recent quarantined files
            alerts.append({
                "id": qf.get('hash', ''),
                "type": "Quarantined File",
                "severity": "high",
                "message": f"File quarantined: {qf.get('original_name', 'Unknown')}",
                "timestamp": qf.get('quarantine_time', datetime.now().isoformat())
            })
        
        # Sort alerts by timestamp
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Calculate threat statistics
        threat_data = {
            "malwareDetected": len(quarantined_files),
            "suspiciousFiles": len(alerts),
            "blockedAttacks": int(len(quarantined_files) * 1.5),  # Estimate
            "networkThreats": len([a for a in alerts if a['severity'] == 'high'])
        }
        
        # Calculate security score based on alerts and quarantined files
        high_alerts = sum(1 for a in alerts if a['severity'] == 'high')
        medium_alerts = sum(1 for a in alerts if a['severity'] == 'medium')
        
        # Higher score is better (fewer severe alerts)
        security_score = 100 - (high_alerts * 15) - (medium_alerts * 5) - (len(quarantined_files) * 10)
        security_score = max(min(security_score, 100), 0)  # Clamp between 0-100
        
        return jsonify({
            "status": "success",
            "data": {
                "metrics": metrics,
                "alerts": alerts,
                "threatData": threat_data,
                "securityScore": security_score,
                "quarantineCount": len(quarantined_files)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting security metrics: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Error getting security metrics: {str(e)}"
        }), 500

@app.route('/api/threat-report', methods=['GET'])
def get_threat_report():
    """
    Get a comprehensive threat report
    
    Returns:
        - JSON with threat statistics and details
    """
    try:
        # Load analysis log if it exists
        analysis_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'analysis_log.json')
        recent_analyses = []
        
        if os.path.exists(analysis_log_path):
            try:
                with open(analysis_log_path, 'r') as f:
                    recent_analyses = json.load(f)
            except Exception as e:
                logger.error(f"Error reading analysis log: {str(e)}")
        
        # Get quarantined files
        quarantined_files = detector.mitigation_handler.list_quarantined_files()
        
        # Calculate statistics
        total_files = len(recent_analyses)
        high_risk = sum(1 for a in recent_analyses if a.get('riskScore', 0) > 0.7)
        medium_risk = sum(1 for a in recent_analyses if 0.4 <= a.get('riskScore', 0) <= 0.7)
        low_risk = total_files - high_risk - medium_risk
        
        # Get extension statistics
        extension_counts = {}
        for analysis in recent_analyses:
            ext = analysis.get('fileExtension', '')
            if ext:
                extension_counts[ext] = extension_counts.get(ext, 0) + 1
        
        # Most common extensions
        top_extensions = sorted(extension_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Format the report
        report = {
            "status": "success",
            "data": {
                "total_files_analyzed": total_files,
                "risk_distribution": {
                    "high_risk": high_risk,
                    "medium_risk": medium_risk,
                    "low_risk": low_risk
                },
                "quarantined_files": len(quarantined_files),
                "top_file_extensions": dict(top_extensions),
                "recent_analyses": recent_analyses[-10:] if recent_analyses else [],  # Last 10 analyses
                "recent_quarantines": quarantined_files[:10]  # Last 10 quarantines
            }
        }
        
        return jsonify(report)
        
    except Exception as e:
        logger.error(f"Error generating threat report: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error generating threat report: {str(e)}"
        }), 500

#--------------------------------------------
# Error Handlers
#--------------------------------------------

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle 413 errors (file too large)"""
    return jsonify({
        "status": "error",
        "message": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024 * 1024)}MB"
    }), 413


if __name__ == "__main__":
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Ransomware Detection and Mitigation API')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to run the server on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    
    args = parser.parse_args()
    
    # Start the server
    port = int(os.environ.get('PORT', args.port))
    logger.info(f"Starting Flask API on port {port}")
    app.run(host=args.host, port=port, debug=args.debug)