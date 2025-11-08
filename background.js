class PhishingDetector {
    constructor() {
      this.knownPhishingPatterns = [
        /paypal.*verify/i,
        /account.*suspended/i,
        /urgent.*action/i,
        /confirm.*identity/i,
        /unusual.*activity/i,
        /security.*alert/i,
        /update.*payment/i,
        /verify.*account/i
      ];
      
      this.legitimateDomains = new Set([
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'netflix.com', 'linkedin.com',
        'twitter.com', 'instagram.com', 'github.com', 'stackoverflow.com'
      ]);
      
      this.suspiciousTLDs = new Set([
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'
      ]);
    }
    
    extractFeatures(url, pageContent) {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      const path = urlObj.pathname;
      
      const features = {
        // URL-based features
        urlLength: url.length,
        domainLength: domain.length,
        pathLength: path.length,
        hasSuspiciousTLD: this.hasSuspiciousTLD(domain),
        hasIPAddress: this.hasIPAddress(domain),
        hasSubdomainCount: (domain.match(/\./g) || []).length,
        hasHttps: url.startsWith('https'),
        hasSuspiciousKeywords: this.hasSuspiciousKeywords(url),
        hasHomographAttack: this.detectHomographs(domain),
        
        // Content-based features
        hasLoginForm: false,
        hasPasswordField: false,
        externalLinksCount: 0,
        suspiciousTextPatterns: 0,
        hasHiddenIframes: false,
        formActionExternal: false,
        
        // Domain reputation
        isKnownLegit: this.isKnownLegitimate(domain),
        domainAge: null,
        sslCertValid: urlObj.protocol === 'https:'
      };
      
      // Content analysis
      if (pageContent) {
        features.hasLoginForm = /<form[^>]*>/i.test(pageContent);
        features.hasPasswordField = /<input[^>]*type=["']?password["']?/i.test(pageContent);
        features.externalLinksCount = this.countExternalLinks(pageContent, domain);
        features.suspiciousTextPatterns = this.countSuspiciousPatterns(pageContent);
        features.hasHiddenIframes = /<iframe[^>]*hidden/i.test(pageContent);
      }
      
      return features;
    }
    
    hasSuspiciousTLD(domain) {
      return Array.from(this.suspiciousTLDs).some(tld => domain.endsWith(tld));
    }
    
    hasIPAddress(domain) {
      return /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || /^\[?[0-9a-fA-F:]+\]?$/.test(domain);
    }
    
    hasSuspiciousKeywords(url) {
      const suspicious = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm'];
      return suspicious.some(keyword => url.toLowerCase().includes(keyword));
    }
    
    detectHomographs(domain) {
      const homoglyphs = {
        'a': ['а', 'ạ', 'ả', 'ã'],
        'e': ['е', 'ẹ', 'ẻ', 'ẽ'],
        'o': ['о', 'ọ', 'ỏ', 'õ'],
        'i': ['і', 'ị', 'ỉ', 'ĩ'],
        'c': ['с', 'ϲ'],
        'p': ['р', 'ρ'],
        'x': ['х', 'ⅹ']
      };
      
      for (let char of domain) {
        for (let [latin, lookalikes] of Object.entries(homoglyphs)) {
          if (lookalikes.includes(char)) return true;
        }
      }
      return false;
    }
    
    isKnownLegitimate(domain) {
      const baseDomain = domain.split('.').slice(-2).join('.');
      return this.legitimateDomains.has(baseDomain);
    }
    
    countExternalLinks(html, currentDomain) {
      const linkRegex = /<a[^>]+href=["']?(https?:\/\/([^"'\s>]+))["']?/gi;
      let count = 0;
      let match;
      
      while ((match = linkRegex.exec(html)) !== null) {
        const linkDomain = new URL(match[1]).hostname;
        if (!linkDomain.includes(currentDomain)) count++;
      }
      
      return count;
    }
    
    countSuspiciousPatterns(content) {
      let count = 0;
      for (let pattern of this.knownPhishingPatterns) {
        if (pattern.test(content)) count++;
      }
      return count;
    }
    
    calculateRiskScore(features) {
      let score = 0;
      const weights = {
        urlLength: features.urlLength > 75 ? 10 : 0,
        domainLength: features.domainLength > 30 ? 8 : 0,
        hasSuspiciousTLD: features.hasSuspiciousTLD ? 25 : 0,
        hasIPAddress: features.hasIPAddress ? 30 : 0,
        hasSubdomainCount: features.hasSubdomainCount > 3 ? 15 : 0,
        hasHttps: features.hasHttps ? -10 : 15,
        hasSuspiciousKeywords: features.hasSuspiciousKeywords ? 12 : 0,
        hasHomographAttack: features.hasHomographAttack ? 35 : 0,
        hasLoginForm: features.hasLoginForm && !features.hasHttps ? 20 : 0,
        hasPasswordField: features.hasPasswordField ? 10 : 0,
        externalLinksCount: features.externalLinksCount > 10 ? 15 : 0,
        suspiciousTextPatterns: features.suspiciousTextPatterns * 8,
        hasHiddenIframes: features.hasHiddenIframes ? 20 : 0,
        isKnownLegit: features.isKnownLegit ? -50 : 0
      };
      
      for (let [key, value] of Object.entries(weights)) {
        score += value;
      }
      
      return Math.max(0, Math.min(100, score));
    }
    
    async analyzeURL(url, pageContent = null) {
      try {
        const features = this.extractFeatures(url, pageContent);
        const riskScore = this.calculateRiskScore(features);
        
        let riskLevel = 'safe';
        if (riskScore >= 70) riskLevel = 'high';
        else if (riskScore >= 40) riskLevel = 'medium';
        else if (riskScore >= 20) riskLevel = 'low';
        
        return {
          url,
          riskScore,
          riskLevel,
          features,
          timestamp: Date.now(),
          isPhishing: riskScore >= 40
        };
      } catch (error) {
        console.error('Analysis error:', error);
        return null;
      }
    }
  }
  
  const detector = new PhishingDetector();
  
  chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId === 0) {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.id === details.tabId) {
          chrome.tabs.sendMessage(details.tabId, { action: 'analyzeCurrentPage' });
        }
      } catch (error) {
        console.error('Navigation handler error:', error);
      }
    }
  });
  
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeURL') {
      detector.analyzeURL(request.url, request.pageContent).then(result => {
        sendResponse(result);
        
        if (result && result.isPhishing) {
          chrome.tabs.sendMessage(sender.tab.id, {
            action: 'showWarning',
            data: result
          });
        }
      });
      return true;
    }
    
    if (request.action === 'getAnalysis') {
      chrome.storage.local.get(['lastAnalysis'], (data) => {
        sendResponse(data.lastAnalysis || null);
      });
      return true;
    }
  });