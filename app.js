// Mitigation Attempt 1:  
// Mitigation is working But the risk score is 50% for all the files. This means that the model is not working properly. This is a very serious issue.


/**
 * Frontend JavaScript for Ransomware Detection and Mitigation System
 * Handles user interactions and communication with the backend API
 */

document.addEventListener("DOMContentLoaded", function() {
    // Get DOM elements
    const detectButton = document.getElementById("detectButton");
    const statusUpdates = document.getElementById("statusUpdates");
    const recommendations = document.getElementById("recommendations");
    const fileInput = document.getElementById("fileInput");
    const incidentDetails = document.getElementById("incidentDetails");
    const autoQuarantineCheckbox = document.getElementById("autoQuarantine");
    const quarantineListBtn = document.getElementById("quarantineListBtn");
    const quarantineList = document.getElementById("quarantineList");
    
    // Add event listener for file input changes to show selected file
    if (fileInput) {
        fileInput.addEventListener("change", function() {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const fileSize = (file.size / 1024).toFixed(2);
                // Remove any previous selected-file divs
                const prevSelection = document.querySelector(".selected-file");
                if (prevSelection) {
                    prevSelection.remove();
                }
                
                // Add new selection info
                document.querySelector(".file-upload-container").insertAdjacentHTML(
                    'beforeend',
                    `<div class="selected-file" style="color: #00FF6A; margin-top: 10px;">
                        Selected: ${file.name} (${fileSize} KB)
                    </div>`
                );
            }
        });
    }
    
    // Function to update status with loading message
    function showLoading() {
        if (statusUpdates) {
            statusUpdates.innerHTML = "<p>Analyzing, please wait...</p>";
        }
        
        if (recommendations) {
            recommendations.innerHTML = "<li>Processing your request...</li>";
        }
        
        if (detectButton) {
            detectButton.disabled = true;
            detectButton.textContent = "Analyzing...";
        }
    }
    
    // Function to restore button state
    function resetButton() {
        if (detectButton) {
            detectButton.disabled = false;
            detectButton.textContent = "Detect & Mitigate";
        }
    }
    
    // Function to format risk score with color coding
    function formatRiskScore(score) {
        const percent = (score * 100).toFixed(1);
        let color = "#4CAF50"; // Green for low risk
        
        if (score > 0.7) {
            color = "#F44336"; // Red for high risk
        } else if (score > 0.4) {
            color = "#FFC107"; // Yellow/amber for medium risk
        }
        
        return `<span style="color: ${color}; font-weight: bold;">${percent}%</span>`;
    }
    
    // Function to display error message
    function showError(message) {
        if (statusUpdates) {
            statusUpdates.innerHTML = `<p style="color: #F44336;">Error: ${message}</p>`;
        }
        
        if (recommendations) {
            recommendations.innerHTML = "<li>Please try again or contact support if the issue persists.</li>";
        }
        
        resetButton();
    }
    
    // Function to analyze file
    async function analyzeFile(file, autoQuarantine) {
        try {
            showLoading();
            
            // Create FormData object
            const formData = new FormData();
            formData.append('file', file);
            
            // Add auto-quarantine parameter if checked
            if (autoQuarantine) {
                formData.append('auto_quarantine', 'true');
            }
            
            // Send request to API
            const response = await fetch("/api/analyze", {
                method: "POST",
                body: formData
            });
            
            // Parse response
            const result = await response.json();
            
            // Reset button state
            resetButton();
            
            // Handle error
            if (result.status === "error") {
                showError(result.message);
                return null;
            }
            
            // Extract data from result
            return result.data;
            
        } catch (error) {
            console.error("Analysis error:", error);
            showError("Network error or server not responding");
            resetButton();
            return null;
        }
    }
    
    // Function to get mitigation recommendations
    async function getMitigationReport(file) {
        try {
            // Create FormData object
            const formData = new FormData();
            formData.append('file', file);
            
            // Send request to API
            const response = await fetch("/api/mitigate", {
                method: "POST",
                body: formData
            });
            
            // Parse response
            const result = await response.json();
            
            // Handle error
            if (result.status === "error") {
                console.error("Mitigation error:", result.message);
                return null;
            }
            
            // Return mitigation report
            return result.data;
            
        } catch (error) {
            console.error("Mitigation error:", error);
            return null;
        }
    }
    
    // Function to report an incident
    async function reportIncident(details) {
        try {
            // Create request body
            const requestBody = {
                description: details,
                severity: "medium", // Default to medium severity
                affectedSystems: ["workstation"] // Default affected system
            };
            
            // Send request to API
            const response = await fetch("/api/incident", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(requestBody)
            });
            
            // Parse response
            const result = await response.json();
            
            // Show result
            if (result.status === "success") {
                const successMessage = document.createElement("p");
                successMessage.textContent = "Incident reported successfully.";
                successMessage.style.color = "#00FF6A";
                statusUpdates.appendChild(successMessage);
                
                // Add recommendations if available
                if (result.data && result.data.mitigation_recommendations) {
                    const recTitle = document.createElement("h3");
                    recTitle.textContent = "Incident Response Recommendations:";
                    recTitle.style.color = "#00FF6A";
                    recommendations.appendChild(recTitle);
                    
                    result.data.mitigation_recommendations.forEach(rec => {
                        const li = document.createElement("li");
                        li.textContent = rec;
                        recommendations.appendChild(li);
                    });
                }
                
                // Clear textarea
                if (incidentDetails) {
                    incidentDetails.value = "";
                }
            } else {
                const errorMessage = document.createElement("p");
                errorMessage.textContent = `Error reporting incident: ${result.message || "Unknown error"}`;
                errorMessage.style.color = "#F44336";
                statusUpdates.appendChild(errorMessage);
            }
            
        } catch (error) {
            console.error("Incident reporting error:", error);
            const errorMessage = document.createElement("p");
            errorMessage.textContent = `Network error reporting incident. Please try again.`;
            errorMessage.style.color = "#F44336";
            statusUpdates.appendChild(errorMessage);
        }
    }
    
    // Function to update UI with analysis results and mitigation recommendations
    function updateUIWithResults(data, mitigationReport) {
        // Update status display
        if (statusUpdates) {
            // Format file size
            const fileSize = data.file_size > 1024 * 1024
                ? `${(data.file_size / (1024 * 1024)).toFixed(2)} MB`
                : `${(data.file_size / 1024).toFixed(2)} KB`;
                
            let statusHTML = `
                <p>Analysis complete for: <strong>${data.file_name}</strong></p>
                <p>Risk Score: ${formatRiskScore(data.risk_score)}</p>
                <p>Risk Level: <strong>${data.risk_level.toUpperCase()}</strong></p>
                <p>File Size: ${fileSize}</p>
                <p>File Hash: ${data.hash || 'Not available'}</p>
                <p>Analyzed: ${new Date().toLocaleTimeString()}</p>
            `;
            
            // Add quarantine status if available
            if (data.quarantined) {
                statusHTML += `
                    <p style="color: #00FF6A;"><strong>File has been automatically quarantined</strong></p>
                `;
            }
            
            statusUpdates.innerHTML = statusHTML;
            
            // Add mitigation report section if available
            if (mitigationReport && mitigationReport.mitigation_report) {
                const report = mitigationReport.mitigation_report;
                
                // Create mitigation report section
                const reportSection = document.createElement("div");
                reportSection.className = "mitigation-report";
                reportSection.innerHTML = `
                    <h3 style="color: #00FF6A; margin-top: 20px;">Mitigation Report</h3>
                    <p>${report.summary}</p>
                `;
                
                // Add detailed steps if available
                if (report.detailed_steps && report.detailed_steps.length > 0) {
                    const stepsTitle = document.createElement("h4");
                    stepsTitle.textContent = "Detailed Mitigation Steps:";
                    stepsTitle.style.color = "#FFC107";
                    reportSection.appendChild(stepsTitle);
                    
                    const stepsList = document.createElement("ol");
                    report.detailed_steps.forEach(step => {
                        const li = document.createElement("li");
                        li.textContent = step.replace(/^\d+\.\s/, ''); // Remove leading numbers
                        stepsList.appendChild(li);
                    });
                    reportSection.appendChild(stepsList);
                }
                
                statusUpdates.appendChild(reportSection);
            }
        }
        
        // Update recommendations
        if (recommendations) {
            recommendations.innerHTML = "";
            
            // Add threats first if they exist
            if (data.threats && data.threats.length > 0) {
                const threatsList = document.createElement("div");
                threatsList.innerHTML = "<h3 style='color: #F44336; margin-top: 0;'>Detected Threats:</h3>";
                
                const threatItems = document.createElement("ul");
                threatItems.style.marginBottom = "20px";
                
                data.threats.forEach(threat => {
                    const li = document.createElement("li");
                    li.textContent = threat;
                    li.style.color = "#F44336";
                    threatItems.appendChild(li);
                });
                
                threatsList.appendChild(threatItems);
                recommendations.appendChild(threatsList);
            }
            
            // Add recommendations
            if (data.recommendations && data.recommendations.length > 0) {
                const recommendationsTitle = document.createElement("h3");
                recommendationsTitle.textContent = "Recommendations:";
                recommendationsTitle.style.color = "#00FF6A";
                recommendationsTitle.style.marginTop = "0";
                recommendations.appendChild(recommendationsTitle);
                
                const recommendationsList = document.createElement("ul");
                data.recommendations.forEach(rec => {
                    const li = document.createElement("li");
                    li.textContent = rec;
                    recommendationsList.appendChild(li);
                });
                recommendations.appendChild(recommendationsList);
            }
            
            // Add mitigation actions if available
            if (data.mitigation_actions && data.mitigation_actions.length > 0) {
                const actionsTitle = document.createElement("h3");
                actionsTitle.textContent = "Suggested Actions:";
                actionsTitle.style.color = "#00FF6A";
                actionsTitle.style.marginTop = "20px";
                recommendations.appendChild(actionsTitle);
                
                const actionsList = document.createElement("ul");
                data.mitigation_actions.forEach(action => {
                    const li = document.createElement("li");
                    li.textContent = action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                    actionsList.appendChild(li);
                });
                recommendations.appendChild(actionsList);
            }
            
            // Add prevention measures if available from mitigation report
            if (mitigationReport && mitigationReport.mitigation_report && mitigationReport.mitigation_report.prevention_measures) {
                const measures = mitigationReport.mitigation_report.prevention_measures;
                if (measures.length > 0) {
                    const preventionTitle = document.createElement("h3");
                    preventionTitle.textContent = "Prevention Measures:";
                    preventionTitle.style.color = "#00FF6A";
                    preventionTitle.style.marginTop = "20px";
                    recommendations.appendChild(preventionTitle);
                    
                    const preventionList = document.createElement("ul");
                    measures.forEach(measure => {
                        const li = document.createElement("li");
                        li.textContent = measure.replace(/^\d+\.\s/, ''); // Remove leading numbers
                        preventionList.appendChild(li);
                    });
                    recommendations.appendChild(preventionList);
                }
            }
        }
    }
    
    // Function to load and display quarantined files
    async function loadQuarantinedFiles() {
        try {
            // Send request to API
            const response = await fetch("/api/quarantine/list");
            
            // Parse response
            const result = await response.json();
            
            // Handle error
            if (result.status === "error") {
                quarantineList.innerHTML = `<p style="color: #F44336;">Error: ${result.message}</p>`;
                return;
            }
            
            // Get quarantined files
            const files = result.data.files;
            
            // Update UI
            if (files.length === 0) {
                quarantineList.innerHTML = "<p>No quarantined files found.</p>";
                return;
            }
            
            // Sort files by quarantine time (newest first)
            files.sort((a, b) => new Date(b.quarantine_time) - new Date(a.quarantine_time));
            
            // Create table
            let tableHTML = `
                <table class="quarantine-table">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Quarantine Time</th>
                            <th>Size</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            // Add rows
            files.forEach(file => {
                const quarantineDate = new Date(file.quarantine_time).toLocaleString();
                const fileSize = (file.file_size / 1024).toFixed(2) + ' KB';
                
                tableHTML += `
                    <tr>
                        <td>${file.original_name}</td>
                        <td>${quarantineDate}</td>
                        <td>${fileSize}</td>
                        <td>
                            <button class="action-btn delete-btn" data-id="${file.hash}">Delete</button>
                            <button class="action-btn restore-btn" data-id="${file.hash}">Restore</button>
                        </td>
                    </tr>
                `;
            });
            
            tableHTML += `
                    </tbody>
                </table>
            `;
            
            quarantineList.innerHTML = tableHTML;
            
            // Add event listeners for action buttons
            document.querySelectorAll('.delete-btn').forEach(button => {
                button.addEventListener('click', async function() {
                    const id = this.getAttribute('data-id');
                    await deleteFromQuarantine(id);
                });
            });
            
            document.querySelectorAll('.restore-btn').forEach(button => {
                button.addEventListener('click', async function() {
                    const id = this.getAttribute('data-id');
                    await restoreFromQuarantine(id);
                });
            });
            
        } catch (error) {
            console.error("Error loading quarantined files:", error);
            quarantineList.innerHTML = `
                <p style="color: #F44336;">Error loading quarantined files: ${error.message}</p>
            `;
        }
    }
    
    // Function to delete file from quarantine
    async function deleteFromQuarantine(id) {
        try {
            // Confirm deletion
            if (!confirm("Are you sure you want to delete this file from quarantine?")) {
                return;
            }
            
            // Send request to API
            const response = await fetch(`/api/quarantine/${id}`, {
                method: "DELETE"
            });
            
            // Parse response
            const result = await response.json();
            
            // Handle result
            if (result.status === "success") {
                alert("File deleted from quarantine successfully");
                // Reload quarantined files
                loadQuarantinedFiles();
            } else {
                alert(`Error deleting file: ${result.message}`);
            }
            
        } catch (error) {
            console.error("Error deleting file:", error);
            alert(`Error deleting file: ${error.message}`);
        }
    }
    
    // Function to restore file from quarantine
    async function restoreFromQuarantine(id) {
        try {
            // Ask for restore path
            const restorePath = prompt("Enter restore path (leave empty to restore to original location):");
            
            // Create request body
            const requestBody = {};
            if (restorePath && restorePath.trim() !== '') {
                requestBody.restore_path = restorePath;
            }
            
            // Send request to API
            const response = await fetch(`/api/quarantine/${id}/restore`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(requestBody)
            });
            
            // Parse response
            const result = await response.json();
            
            // Handle result
            if (result.status === "success") {
                alert(`File restored successfully to ${result.data.restore_path}`);
                // Reload quarantined files
                loadQuarantinedFiles();
            } else {
                alert(`Error restoring file: ${result.message}`);
            }
            
        } catch (error) {
            console.error("Error restoring file:", error);
            alert(`Error restoring file: ${error.message}`);
        }
    }
    
    // Function to check API status
    async function checkApiStatus() {
        try {
            const response = await fetch("/api/status");
            const data = await response.json();
            
            // Update footer with status
            const footer = document.querySelector("footer");
            if (footer) {
                if (data.status === "online") {
                    footer.innerHTML = `<p>© 2025 CyberShield. All Rights Reserved. <span style="color: #00FF6A;">System Online</span></p>`;
                } else if (data.status === "degraded") {
                    footer.innerHTML = `<p>© 2025 CyberShield. All Rights Reserved. <span style="color: #FFC107;">Limited Functionality</span></p>`;
                } else {
                    footer.innerHTML = `<p>© 2025 CyberShield. All Rights Reserved. <span style="color: #F44336;">System Offline</span></p>`;
                }
            }
            
            // If quarantine list button exists, add event listener
            if (quarantineListBtn) {
                quarantineListBtn.addEventListener('click', function() {
                    // Toggle quarantine list visibility
                    if (quarantineList.style.display === 'none' || !quarantineList.style.display) {
                        quarantineList.style.display = 'block';
                        this.textContent = 'Hide Quarantine List';
                        loadQuarantinedFiles();
                    } else {
                        quarantineList.style.display = 'none';
                        this.textContent = 'Show Quarantine List';
                    }
                });
            }
            
            return true;
            
        } catch (error) {
            console.error("API status check failed:", error);
            
            // Update UI to show the system might have issues
            const footer = document.querySelector("footer");
            if (footer) {
                footer.innerHTML = `<p>© 2025 CyberShield. All Rights Reserved. <span style="color: #F44336;">Cannot Connect to Server</span></p>`;
            }
            
            return false;
        }
    }
    
    // Handle detect button click
    if (detectButton) {
        detectButton.addEventListener("click", async function() {
            // Clear previous status
            if (statusUpdates) {
                statusUpdates.innerHTML = "";
            }
            
            if (recommendations) {
                recommendations.innerHTML = "";
            }
            
            // Check if we have a file to analyze
            const hasFile = fileInput && fileInput.files.length > 0;
            
            // Check if we have incident details to report
            const details = incidentDetails ? incidentDetails.value.trim() : "";
            const hasIncidentDetails = details !== "";
            
            // If neither file nor incident details, show error
            if (!hasFile && !hasIncidentDetails) {
                showError("Please upload a file or describe suspicious activity");
                return;
            }
            
            // If we have a file, analyze it
            if (hasFile) {
                const file = fileInput.files[0];
                const shouldAutoQuarantine = autoQuarantineCheckbox && autoQuarantineCheckbox.checked;
                
                // First analyze the file
                const analysisResult = await analyzeFile(file, shouldAutoQuarantine);
                if (!analysisResult) {
                    return; // Error occurred during analysis
                }
                
                // Get mitigation recommendations
                const mitigationReport = await getMitigationReport(file);
                
                // Update UI with results
                updateUIWithResults(analysisResult, mitigationReport);
            }
            
            // If we have incident details, report them
            if (hasIncidentDetails) {
                await reportIncident(details);
            }
        });
    }
    
    // Check API status on page load and set up event listeners
    checkApiStatus();
});