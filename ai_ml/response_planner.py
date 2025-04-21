# # response_planner.py

# class IncidentResponse:
#     def __init__(self):
#         self.plan = ["Analyze", "Contain", "Eradicate", "Recover"]

#     def execute_plan(self):
#         """Execute the incident response plan step by step."""
#         print("Starting Incident Response Plan...")
#         for step in self.plan:
#             self.execute_step(step)
#         print("Incident Response Plan executed successfully.")

#     def execute_step(self, step):
#         """Execute a specific step in the incident response plan."""
#         if step == "Analyze":
#             self.analyze()
#         elif step == "Contain":
#             self.contain()
#         elif step == "Eradicate":
#             self.eradicate()
#         elif step == "Recover":
#             self.recover()
#         else:
#             print(f"Unknown step: {step}")

#     def analyze(self):
#         """Analyze the attack to understand its scope and impact."""
#         print("Analyzing the ransomware attack...")

#     def contain(self):
#         """Contain the spread of the ransomware."""
#         print("Containing the ransomware spread...")

#     def eradicate(self):
#         """Eradicate the ransomware from affected systems."""
#         print("Eradicating ransomware from systems...")

#     def recover(self):
#         """Recover data and restore systems to normal operations."""
#         print("Recovering data and restoring systems...")

# if __name__ == "__main__":
#     incident_response = IncidentResponse()
#     incident_response.execute_plan()





#code 2: claude attempt 1

# response_planner.py
import logging
import json
import smtplib
import subprocess
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from threading import Lock
import sqlite3

class EnhancedIncidentResponse:
    def __init__(self):
        self.db_path = 'incidents.db'
        self.lock = Lock()
        self.response_stages = [
            "Detection",
            "Analysis",
            "Containment",
            "Eradication",
            "Recovery",
            "Post-Incident"
        ]
        self.current_stage = None
        self.incident_id = None
        self.setup_logging()
        self.init_database()
        self.load_config()

    def setup_logging(self):
        """Configure logging for incident response"""
        self.logger = logging.getLogger("IncidentResponse")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler("incident_response.log")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def init_database(self):
        """Initialize SQLite database for incident tracking"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        type TEXT,
                        severity TEXT,
                        status TEXT,
                        details TEXT
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS response_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id INTEGER,
                        timestamp TEXT,
                        action TEXT,
                        result TEXT,
                        FOREIGN KEY (incident_id) REFERENCES incidents (id)
                    )
                ''')
                conn.commit()
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")

    def load_config(self):
        """Load response configuration settings"""
        try:
            with open('response_config.json', 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {
                'notification_emails': ['security@company.com'],
                'severity_levels': ['Low', 'Medium', 'High', 'Critical'],
                'automated_responses': True,
                'backup_location': '/backup/ransomware'
            }
            self.save_config()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")

    def save_config(self):
        """Save current configuration to file"""
        try:
            with open('response_config.json', 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")

    def create_incident(self, incident_type: str, severity: str, details: Dict) -> int:
        """Create a new incident record"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO incidents (timestamp, type, severity, status, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    incident_type,
                    severity,
                    'Active',
                    json.dumps(details)
                ))
                conn.commit()
                self.incident_id = cursor.lastrowid
                self.notify_stakeholders(f"New {severity} incident created: {incident_type}")
                return self.incident_id
        except Exception as e:
            self.logger.error(f"Error creating incident: {e}")
            return None

    def execute_response_plan(self, incident_id: int) -> bool:
        """Execute the incident response plan"""
        try:
            self.incident_id = incident_id
            for stage in self.response_stages:
                self.current_stage = stage
                self.log_response_action(stage, "Started")
                
                if stage == "Detection":
                    self.handle_detection()
                elif stage == "Analysis":
                    self.analyze_incident()
                elif stage == "Containment":
                    self.contain_incident()
                elif stage == "Eradication":
                    self.eradicate_threat()
                elif stage == "Recovery":
                    self.initiate_recovery()
                elif stage == "Post-Incident":
                    self.post_incident_analysis()
                
                self.log_response_action(stage, "Completed")
            
            return True
        except Exception as e:
            self.logger.error(f"Error executing response plan: {e}")
            return False

    def handle_detection(self):
        """Handle the detection phase"""
        try:
            # Gather initial incident information
            incident_info = self.get_incident_details(self.incident_id)
            
            # Initial assessment
            if incident_info['severity'] == 'Critical':
                self.notify_stakeholders("Critical incident detected - immediate response required")
                self.implement_emergency_measures()
        except Exception as e:
            self.logger.error(f"Error in detection phase: {e}")

    def analyze_incident(self):
        """Analyze the incident in detail"""
        try:
            # Collect system information
            if os.name == 'nt': 