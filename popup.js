document.addEventListener('DOMContentLoaded', async () => {
    const contentDiv = document.getElementById('content');
    
    chrome.runtime.sendMessage({ action: 'getAnalysis' }, (analysis) => {
      if (!analysis) {
        contentDiv.innerHTML = `
          <div class="status-card">
            <p style="margin: 0; text-align: center; color: #6b7280;">
              No analysis available for this page
            </p>
          </div>
        `;
        return;
      }
      
      const statusClass = analysis.riskLevel === 'safe' ? 'safe' : 
                          analysis.riskLevel === 'low' ? 'safe' :
                          analysis.riskLevel === 'medium' ? 'warning' : 'danger';
      
      const statusText = analysis.isPhishing ? 'Potential Phishing Detected' : 'Website Appears Safe';
      const statusIcon = analysis.isPhishing ? '⚠️' : '✓';
      
      const riskColor = analysis.riskScore >= 70 ? '#dc2626' :
                        analysis.riskScore >= 40 ? '#ea580c' :
                        analysis.riskScore >= 20 ? '#f59e0b' : '#16a34a';
      
      contentDiv.innerHTML = `
        <div class="status-card">
          <div class="status-indicator">
            <div class="status-icon ${statusClass}">
              <span style="font-size: 24px;">${statusIcon}</span>
            </div>
            <div class="status-text">
              <h2>${statusText}</h2>
              <p>${new Date(analysis.timestamp).toLocaleString()}</p>
            </div>
          </div>
          
          <div class="risk-score">
            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
              <span style="font-size: 13px; color: #6b7280; font-weight: 600;">Risk Score</span>
              <span style="font-size: 15px; font-weight: 700; color: ${riskColor};">${analysis.riskScore}%</span>
            </div>
            <div class="risk-bar">
              <div class="risk-fill" style="width: ${analysis.riskScore}%; background: ${riskColor};"></div>
            </div>
          </div>
          
          <div class="features">
            <div class="feature-item">
              <span class="feature-label">HTTPS</span>
              <span class="feature-value">${analysis.features.hasHttps ? '✓ Yes' : '✗ No'}</span>
            </div>
            <div class="feature-item">
              <span class="feature-label">IP-based URL</span>
              <span class="feature-value">${analysis.features.hasIPAddress ? '✗ Yes' : '✓ No'}</span>
            </div>
            <div class="feature-item">
              <span class="feature-label">Login Form</span>
              <span class="feature-value">${analysis.features.hasLoginForm ? 'Detected' : 'None'}</span>
            </div>
            <div class="feature-item">
              <span class="feature-label">Suspicious Patterns</span>
              <span class="feature-value">${analysis.features.suspiciousTextPatterns}</span>
            </div>
          </div>
        </div>
      `;
    });
  });

  console.log('PhishAgent Extension - Background Service Worker Initialized');