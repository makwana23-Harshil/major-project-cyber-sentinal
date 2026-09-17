/**
 * Cyber Sentinel - Explainable AI (XAI) & Model Metrics Viewer
 */

const ExplainabilityView = {

  async loadMetrics() {
    try {
      const data = await App.apiRequest('/api/model/metrics');
      this.renderModelMetrics(data);
    } catch (err) {
      console.error('Failed to load model metrics:', err);
    }
  },

  renderModelMetrics(data) {
    const urlM = data.url_classifier;
    const textM = data.text_classifier;

    if (urlM) {
      document.getElementById('metricURLAccuracy').innerText = `${(urlM.accuracy * 100).toFixed(1)}%`;
      document.getElementById('metricURLPrecision').innerText = `${(urlM.precision * 100).toFixed(1)}%`;
      document.getElementById('metricURLRecall').innerText = `${(urlM.recall * 100).toFixed(1)}%`;
      document.getElementById('metricURLF1').innerText = `${(urlM.f1_score * 100).toFixed(1)}%`;

      const barsContainer = document.getElementById('urlFeatureBars');
      if (barsContainer && urlM.top_features) {
        barsContainer.innerHTML = urlM.top_features.map(f => {
          const pct = (f.importance * 100).toFixed(1);
          return `
            <div>
              <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 2px;">
                <span class="input-mono">${f.feature}</span>
                <span style="font-weight: 700; color: var(--cyber-blue);">${pct}%</span>
              </div>
              <div style="height: 6px; background: rgba(255,255,255,0.06); border-radius: var(--radius-full); overflow: hidden;">
                <div style="width: ${Math.min(100, f.importance * 350)}%; height: 100%; background: linear-gradient(90deg, #06b6d4, #3b82f6); border-radius: var(--radius-full);"></div>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    if (textM) {
      document.getElementById('metricTextAccuracy').innerText = `${(textM.accuracy * 100).toFixed(1)}%`;
      document.getElementById('metricTextPrecision').innerText = `${(textM.precision * 100).toFixed(1)}%`;
      document.getElementById('metricTextRecall').innerText = `${(textM.recall * 100).toFixed(1)}%`;
      document.getElementById('metricTextF1').innerText = `${(textM.f1_score * 100).toFixed(1)}%`;

      const tokenWeightsContainer = document.getElementById('textTokenWeights');
      if (tokenWeightsContainer && textM.top_phishing_tokens) {
        tokenWeightsContainer.innerHTML = textM.top_phishing_tokens.map(t => {
          return `
            <span class="xai-highlight xai-threat" title="Model Coefficient: +${t.weight}" style="font-size: 0.78rem;">
              ${t.token} <small style="color: rgba(255,255,255,0.6); font-size: 0.68rem;">+${t.weight.toFixed(2)}</small>
            </span>
          `;
        }).join('');
      }
    }
  }
};
