/**
 * Cyber Sentinel - Threat Scanners (URL, Email, Message)
 */

const Scanners = {
  
  // ==========================================
  // URL SCANNER
  // ==========================================
  
  setURLPreset(url) {
    const input = document.getElementById('urlInput');
    if (input) {
      input.value = url;
      this.handleURLScan(new Event('submit'));
    }
  },

  resetURLScanner() {
    document.getElementById('urlInput').value = '';
    document.getElementById('urlResultContainer').style.display = 'none';
    document.getElementById('urlResultContainer').innerHTML = '';
  },

  async handleURLScan(event) {
    if (event) event.preventDefault();
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;

    const loader = document.getElementById('urlScanLoader');
    const resultContainer = document.getElementById('urlResultContainer');
    const btn = document.getElementById('btnScanURL');

    loader.style.display = 'block';
    resultContainer.style.display = 'none';
    btn.disabled = true;

    try {
      const data = await App.apiRequest('/api/scan/url', {
        method: 'POST',
        body: JSON.stringify({ url, deep_analysis: true })
      });

      this.renderScanResult(resultContainer, data);
      App.showToast(`URL Scan Completed: ${data.prediction}`, data.prediction === 'Real / Safe' ? 'success' : 'error');
    } catch (err) {
      // Handled in apiRequest
    } finally {
      loader.style.display = 'none';
      btn.disabled = false;
    }
  },

  // ==========================================
  // EMAIL SCANNER
  // ==========================================

  setEmailPreset(type) {
    const senderEl = document.getElementById('emailSender');
    const subjectEl = document.getElementById('emailSubject');
    const bodyEl = document.getElementById('emailBody');

    if (type === 'safe') {
      senderEl.value = 'Sarah Connor <sarah.connor@cyberdyne.org>';
      subjectEl.value = 'Q3 Cybersecurity Engineering Sync - Agenda';
      bodyEl.value = 'Hi Team,\n\nPlease review the attached sprint retrospective documentation for tomorrow\'s sync at 3:00 PM.\n\nBest,\nSarah';
    } else if (type === 'phish-bank') {
      senderEl.value = '"Chase Security Alerts" <security@chase-fraud-prevention.xyz>';
      subjectEl.value = 'URGENT: Your Chase Account Has Been Restricted!';
      bodyEl.value = 'DEAR VALUED CUSTOMER,\n\nWe detected an unauthorized sign-in attempt from Russia. Your account has been temporarily LOCKED. Verify your identity immediately at http://chase-security-verify.xyz/auth or account will be closed in 12 hours.';
    } else if (type === 'phish-ceo') {
      senderEl.value = '"CEO Richard Hendricks" <richard@piper-corp.top>';
      subjectEl.value = 'CONFIDENTIAL: Urgent Wire Transfer Required';
      bodyEl.value = 'I am currently in an investor meeting and cannot pick up calls. Wire $45,000 immediately to our supplier or send 10 Apple Gift Cards right now for clients.';
    }
    this.handleEmailScan(new Event('submit'));
  },

  resetEmailScanner() {
    document.getElementById('emailSender').value = '';
    document.getElementById('emailSubject').value = '';
    document.getElementById('emailBody').value = '';
    document.getElementById('fileUploadInfo').innerText = '';
    document.getElementById('emailFileUpload').value = '';
    document.getElementById('emailResultContainer').style.display = 'none';
    document.getElementById('emailResultContainer').innerHTML = '';
  },

  async handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    document.getElementById('fileUploadInfo').innerText = `Selected file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    
    const formData = new FormData();
    formData.append('file', file);

    const loader = document.getElementById('emailScanLoader');
    const resultContainer = document.getElementById('emailResultContainer');

    loader.style.display = 'block';
    resultContainer.style.display = 'none';

    try {
      const response = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error('File scan failed');
      }

      const data = await response.json();
      this.renderScanResult(resultContainer, data);
      App.showToast(`File Analyzed: ${data.prediction}`, data.prediction === 'Real / Safe' ? 'success' : 'error');
    } catch (err) {
      App.showToast(err.message, 'error');
    } finally {
      loader.style.display = 'none';
    }
  },

  async handleEmailScan(event) {
    if (event) event.preventDefault();
    const sender = document.getElementById('emailSender').value.trim();
    const subject = document.getElementById('emailSubject').value.trim();
    const body = document.getElementById('emailBody').value.trim();

    if (!body && !subject) {
      App.showToast('Please provide email body text or upload an email file', 'error');
      return;
    }

    const loader = document.getElementById('emailScanLoader');
    const resultContainer = document.getElementById('emailResultContainer');
    const btn = document.getElementById('btnScanEmail');

    loader.style.display = 'block';
    resultContainer.style.display = 'none';
    btn.disabled = true;

    try {
      const data = await App.apiRequest('/api/scan/email', {
        method: 'POST',
        body: JSON.stringify({ sender, subject, body })
      });

      this.renderScanResult(resultContainer, data);
      App.showToast(`Email Scan Completed: ${data.prediction}`, data.prediction === 'Real / Safe' ? 'success' : 'error');
    } catch (err) {
      // Handled in apiRequest
    } finally {
      loader.style.display = 'none';
      btn.disabled = false;
    }
  },

  // ==========================================
  // MESSAGE / SMS SCANNER
  // ==========================================

  setMessagePreset(type) {
    const input = document.getElementById('messageInput');
    const mockup = document.getElementById('smsLiveMockup');

    if (type === 'safe-otp') {
      input.value = 'Your OTP for transaction of $45.00 at Target is 482913. Valid for 10 minutes. Do not share this OTP with anyone. Reference ID: 938491.';
    } else if (type === 'smishing-bank') {
      input.value = 'URGENT! Your bank account will be blocked by midnight due to pending e-KYC. Verify your identity immediately at http://online-kyc-bank.tk or call customer support.';
    } else if (type === 'smishing-parcel') {
      input.value = 'USPS Notice: Your package delivery has been suspended due to an incomplete address. Pay $2.99 redelivery fee at http://usps-parcel-tracking-fee.click/redelivery to release package.';
    }

    mockup.innerText = input.value;
    this.handleMessageScan(new Event('submit'));
  },

  resetMessageScanner() {
    document.getElementById('messageInput').value = '';
    document.getElementById('smsLiveMockup').innerText = 'Type or select a message to see the simulated shield preview...';
    document.getElementById('msgResultContainer').style.display = 'none';
    document.getElementById('msgResultContainer').innerHTML = '';
  },

  async handleMessageScan(event) {
    if (event) event.preventDefault();
    const message = document.getElementById('messageInput').value.trim();
    if (!message) return;

    document.getElementById('smsLiveMockup').innerText = message;

    const loader = document.getElementById('msgScanLoader');
    const resultContainer = document.getElementById('msgResultContainer');
    const btn = document.getElementById('btnScanMessage');

    loader.style.display = 'block';
    resultContainer.style.display = 'none';
    btn.disabled = true;

    try {
      const data = await App.apiRequest('/api/scan/message', {
        method: 'POST',
        body: JSON.stringify({ message })
      });

      this.renderScanResult(resultContainer, data);
      App.showToast(`Message Scan Completed: ${data.prediction}`, data.prediction === 'Real / Safe' ? 'success' : 'error');
    } catch (err) {
      // Handled in apiRequest
    } finally {
      loader.style.display = 'none';
      btn.disabled = false;
    }
  },

  // ==========================================
  // UNIFIED RESULT RENDERER
  // ==========================================

  renderScanResult(container, data) {
    const isSafe = data.prediction.includes('Safe') || data.prediction.includes('Real');
    const isSuspicious = data.prediction.includes('Suspicious');
    
    let bannerClass = 'verdict-safe';
    let icon = 'REAL / SAFE';
    let scoreColor = 'var(--color-safe)';

    if (isSuspicious) {
      bannerClass = 'verdict-suspicious';
      icon = 'SUSPICIOUS';
      scoreColor = 'var(--color-suspicious)';
    } else if (!isSafe) {
      bannerClass = 'verdict-malicious';
      icon = 'FAKE / MALICIOUS';
      scoreColor = 'var(--color-malicious)';
    }

    const realProb = data.class_probabilities?.real || (isSafe ? data.confidence : (100 - data.confidence));
    const fakeProb = data.class_probabilities?.fake || (!isSafe ? data.confidence : (100 - data.confidence));

    let indicatorsHtml = '';
    if (data.indicators && data.indicators.length > 0) {
      indicatorsHtml = `
        <div class="indicators-panel">
          <div style="font-weight: 700; font-size: 0.95rem; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
            <span>Detected Threat Indicators</span>
            <span class="risk-tag risk-tag-high">${data.indicators.length} Signals</span>
          </div>
          ${data.indicators.map(ind => `
            <div class="indicator-item">
              <span class="indicator-icon">${isSafe ? 'SAFE' : 'WARNING'}</span>
              <div>${ind}</div>
            </div>
          `).join('')}
        </div>
      `;
    } else {
      indicatorsHtml = `
        <div class="indicators-panel">
          <div style="display: flex; align-items: center; gap: 10px; color: var(--color-safe);">
            <span style="font-size: 0.85rem;font-weight:700;">SAFE</span>
            <span style="font-weight: 600;">No malicious triggers or social engineering indicators found.</span>
          </div>
        </div>
      `;
    }

    // Explainable AI preview (highlighted words) if present
    let xaiHtml = '';
    if (data.xai_data?.highlighted_html) {
      xaiHtml = `
        <div style="margin-top: 20px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="font-weight: 700; font-size: 0.9rem;">Explainable AI: Highlighted Threat Tokens</div>
            <span style="font-size: 0.75rem; color: var(--text-dim);">Hover over tokens for risk attribution</span>
          </div>
          <div class="xai-preview-box">${data.xai_data.highlighted_html}</div>
        </div>
      `;
    }

    // URL Feature Inspection Table if URL scan
    let featureTableHtml = '';
    if (data.xai_data?.feature_table) {
      featureTableHtml = `
        <div style="margin-top: 24px;">
          <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 12px;">URL Deep Feature Diagnostics (30+ Attributes)</h4>
          <div style="overflow-x: auto; border: 1px solid var(--border-color); border-radius: var(--radius-md);">
            <table class="feature-table">
              <thead>
                <tr>
                  <th>Feature Name</th>
                  <th>Extracted Value</th>
                  <th>Risk Assessment</th>
                </tr>
              </thead>
              <tbody>
                ${data.xai_data.feature_table.map(f => {
                  const tagClass = f.risk === 'Critical' ? 'risk-tag-critical' : (f.risk === 'High' ? 'risk-tag-high' : (f.risk === 'Medium' ? 'risk-tag-medium' : 'risk-tag-safe'));
                  return `
                    <tr>
                      <td style="font-weight: 600;">${f.name}</td>
                      <td class="input-mono">${f.value}</td>
                      <td><span class="risk-tag ${tagClass}">${f.risk}</span></td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Nested URL scans if email or message contained links
    let nestedUrlsHtml = '';
    if (data.xai_data?.embedded_urls_analysis && data.xai_data.embedded_urls_analysis.length > 0) {
      nestedUrlsHtml = `
        <div style="margin-top: 20px;">
          <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 10px;">Embedded Links Deep Scan</h4>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            ${data.xai_data.embedded_urls_analysis.map(u => `
              <div style="background: var(--bg-surface); border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
                <div class="input-mono" style="font-size: 0.85rem; color: var(--cyber-blue); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 60%;">
                  ${u.url}
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                  <span class="risk-tag ${u.prediction.includes('Malicious') ? 'risk-tag-high' : 'risk-tag-safe'}">${u.prediction}</span>
                  <span style="font-weight: 700; font-size: 0.85rem;">${u.risk_score}/100</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    container.innerHTML = `
      <div class="verdict-banner ${bannerClass}">
        <div>
          <div class="verdict-badge">${icon}</div>
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;">
            Confidence: <b>${data.confidence.toFixed(1)}%</b> • Risk Level: <b>${data.risk_level}</b>
          </div>
        </div>
        <div class="score-gauge-box">
          <div class="score-num" style="color: ${scoreColor};">${data.risk_score}</div>
          <div class="score-label">Cyber Risk Score (0-100)</div>
        </div>
      </div>

      <!-- Probability Distribution Bar -->
      <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; font-size: 0.82rem; font-weight: 600; margin-bottom: 8px;">
          <span style="color: var(--color-safe);">Real / Safe: ${realProb.toFixed(1)}%</span>
          <span style="color: var(--color-malicious);">Fake / Malicious: ${fakeProb.toFixed(1)}%</span>
        </div>
        <div style="height: 10px; background: var(--bg-surface-elevated); border-radius: var(--radius-full); overflow: hidden; display: flex;">
          <div style="width: ${realProb}%; background: var(--color-safe); transition: width 0.6s ease;"></div>
          <div style="width: ${fakeProb}%; background: var(--color-malicious); transition: width 0.6s ease;"></div>
        </div>
      </div>

      ${indicatorsHtml}
      ${xaiHtml}
      ${nestedUrlsHtml}
      ${featureTableHtml}
    `;

    container.style.display = 'block';
  }
};
