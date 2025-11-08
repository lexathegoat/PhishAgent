(function() {
    let warningShown = false;
    
    function getPageContent() {
      return document.documentElement.outerHTML;
    }
    
    function analyzeCurrentPage() {
      if (warningShown) return;
      
      const pageContent = getPageContent();
      const url = window.location.href;
      
      chrome.runtime.sendMessage({
        action: 'analyzeURL',
        url: url,
        pageContent: pageContent
      }, (response) => {
        if (response) {
          chrome.storage.local.set({ lastAnalysis: response });
          
          if (response.isPhishing && !warningShown) {
            showPhishingWarning(response);
          }
        }
      });
    }
    
    function showPhishingWarning(analysis) {
      warningShown = true;
      
      const warningDiv = document.createElement('div');
      warningDiv.id = 'phishagent-warning';
      warningDiv.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        color: white;
        padding: 20px;
        z-index: 999999;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        animation: slideDown 0.3s ease-out;
      `;
      
      const riskColor = analysis.riskLevel === 'high' ? '#fef2f2' : 
                        analysis.riskLevel === 'medium' ? '#fff7ed' : '#fefce8';
      
      warningDiv.innerHTML = `
        <style>
          @keyframes slideDown {
            from { transform: translateY(-100%); }
            to { transform: translateY(0); }
          }
        </style>
        <div style="max-width: 1200px; margin: 0 auto;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 20px;">
            <div style="flex: 1;">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/>
                  <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <h2 style="margin: 0; font-size: 24px; font-weight: 700;">PHISHING WARNING</h2>
              </div>
              <p style="margin: 0 0 12px 44px; font-size: 16px; opacity: 0.95;">
                This website has been identified as potentially dangerous with a risk score of <strong>${analysis.riskScore}%</strong>
              </p>
              <div style="margin-left: 44px; display: flex; gap: 12px; flex-wrap: wrap;">
                <span style="background: ${riskColor}; color: #7f1d1d; padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: 600;">
                  Risk Level: ${analysis.riskLevel.toUpperCase()}
                </span>
                ${analysis.features.hasIPAddress ? '<span style="background: #fef2f2; color: #7f1d1d; padding: 6px 12px; border-radius: 6px; font-size: 13px;">IP-based URL</span>' : ''}
                ${analysis.features.hasSuspiciousTLD ? '<span style="background: #fef2f2; color: #7f1d1d; padding: 6px 12px; border-radius: 6px; font-size: 13px;">Suspicious Domain</span>' : ''}
                ${analysis.features.hasHomographAttack ? '<span style="background: #fef2f2; color: #7f1d1d; padding: 6px 12px; border-radius: 6px; font-size: 13px;">Homograph Attack</span>' : ''}
              </div>
            </div>
            <div style="display: flex; gap: 12px;">
              <button id="phishagent-leave" style="
                background: white;
                color: #dc2626;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 15px;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                transition: all 0.2s;
              ">Leave Site</button>
              <button id="phishagent-ignore" style="
                background: transparent;
                color: white;
                border: 2px solid white;
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 15px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
              ">Ignore Warning</button>
            </div>
          </div>
        </div>
      `;
      
      document.body.insertBefore(warningDiv, document.body.firstChild);
      
      document.getElementById('phishagent-leave').onclick = () => {
        window.location.href = 'about:blank';
      };
      
      document.getElementById('phishagent-ignore').onclick = () => {
        warningDiv.style.animation = 'slideDown 0.3s ease-out reverse';
        setTimeout(() => warningDiv.remove(), 300);
      };
    }
    
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'analyzeCurrentPage') {
        analyzeCurrentPage();
      } else if (request.action === 'showWarning') {
        showPhishingWarning(request.data);
      }
    });
    
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', analyzeCurrentPage);
    } else {
      analyzeCurrentPage();
    }
  })();