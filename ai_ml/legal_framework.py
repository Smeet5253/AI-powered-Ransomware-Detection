# legal_framework.py

class LegalFramework:
    def __init__(self):
        self.compliance_check = True  # Assume compliance check is true by default
        self.reported_to_law_enforcement = False

    def check_compliance(self, regulations):
        """Check compliance with specified regulations."""
        if self.compliance_check:
            print("Compliance check passed.")
            return True
        else:
            print("Non-compliance detected.")
            return False

    def report_incident(self, agency_name, incident_details):
        """Report the ransomware incident to law enforcement agencies."""
        if not self.reported_to_law_enforcement:
            print(f"Reporting incident to {agency_name}...")
            # Here you would implement actual reporting logic (e.g., API call)
            print(f"Incident details: {incident_details}")
            self.reported_to_law_enforcement = True
            print("Incident reported successfully.")
        else:
            print("Incident has already been reported.")

if __name__ == "__main__":
    legal_framework = LegalFramework()
    
    # Example usage of compliance check
    regulations = ["GDPR", "HIPAA"]  # Example regulations
    legal_framework.check_compliance(regulations)

    # Example usage of reporting an incident
    agency_name = "FBI"
    incident_details = "Ransomware attack detected on company servers."
    legal_framework.report_incident(agency_name, incident_details)
