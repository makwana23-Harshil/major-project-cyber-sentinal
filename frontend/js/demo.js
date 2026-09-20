/**
 * Cyber Sentinel - Demo Test Presets Loader
 */

const DemoView = {
  demoSamples: [],

  async loadDemoSamples() {
    try {
      this.demoSamples = await App.apiRequest('/api/demo/samples');
      this.renderDemoCards();
    } catch (err) {
      console.error('Failed to load demo samples:', err);
    }
  },

  renderDemoCards() {
    const container = document.getElementById('demoCardsContainer');
    if (!container) return;

    if (!this.demoSamples || this.demoSamples.length === 0) {
      container.innerHTML = `<div style="color: var(--text-dim);">No demo samples available.</div>`;
      return;
    }

    container.innerHTML = this.demoSamples.map(sample => {
      const isPhish = sample.title.toLowerCase().includes('phishing') || 
                      sample.title.toLowerCase().includes('malicious') || 
                      sample.title.toLowerCase().includes('smishing') ||
                      sample.title.toLowerCase().includes('fraud');
      const badgeClass = isPhish ? 'risk-tag-high' : 'risk-tag-safe';
      const badgeText = isPhish ? 'Malicious Sample' : 'Legitimate Sample';

      return `
        <div class="cyber-card ${isPhish ? 'card-glow-red' : 'card-glow-green'}" style="display: flex; flex-direction: column; justify-content: space-between;">
          <div>
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
              <span class="quick-chip" style="font-size: 0.72rem; text-transform: uppercase;">${sample.category}</span>
              <span class="risk-tag ${badgeClass}">${badgeText}</span>
            </div>
            <h4 style="font-size: 1rem; font-weight: 700; color: #fff; margin-bottom: 6px;">${sample.title}</h4>
            <p style="font-size: 0.82rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 14px;">
              ${sample.description}
            </p>
          </div>
          
          <button class="btn-cyber ${isPhish ? 'btn-danger' : 'btn-primary'} btn-sm" style="width: 100%;" onclick="DemoView.executeDemo('${sample.id}')">
            Load & Scan Scenario
          </button>
        </div>
      `;
    }).join('');
  },

  executeDemo(demoId) {
    const sample = this.demoSamples.find(s => s.id === demoId);
    if (!sample) return;

    if (sample.type === 'url') {
      App.navigateTo('url-scanner');
      document.getElementById('urlInput').value = sample.data.url;
      Scanners.handleURLScan(new Event('submit'));
    } else if (sample.type === 'email') {
      App.navigateTo('email-scanner');
      document.getElementById('emailSender').value = sample.data.sender || '';
      document.getElementById('emailSubject').value = sample.data.subject || '';
      document.getElementById('emailBody').value = sample.data.body || '';
      Scanners.handleEmailScan(new Event('submit'));
    } else if (sample.type === 'message' || sample.type === 'text') {
      App.navigateTo('message-scanner');
      document.getElementById('messageInput').value = sample.data.message || sample.data.text || '';
      document.getElementById('smsLiveMockup').innerText = document.getElementById('messageInput').value;
      Scanners.handleMessageScan(new Event('submit'));
    }
  }
};
