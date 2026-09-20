/**
 * Cyber Sentinel - Threat History & Incident Audit Log
 */

const HistoryView = {
  currentPage: 1,
  pageSize: 12,
  searchTimer: null,

  debounceFetch() {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => {
      this.fetchHistory(1);
    }, 300);
  },

  async fetchHistory(page = 1) {
    this.currentPage = page;
    const search = document.getElementById('historySearchInput')?.value.trim() || '';
    const scanType = document.getElementById('filterType')?.value || 'all';
    const prediction = document.getElementById('filterVerdict')?.value || 'all';
    const riskLevel = document.getElementById('filterRisk')?.value || 'all';

    let url = `/api/history?page=${page}&page_size=${this.pageSize}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (scanType !== 'all') url += `&scan_type=${encodeURIComponent(scanType)}`;
    if (prediction !== 'all') url += `&prediction=${encodeURIComponent(prediction)}`;
    if (riskLevel !== 'all') url += `&risk_level=${encodeURIComponent(riskLevel)}`;

    try {
      const data = await App.apiRequest(url);
      this.renderHistoryTable(data);
      this.updatePagination(data);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  },

  renderHistoryTable(data) {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;

    if (!data.scans || data.scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 32px;">
            No scan logs match your search or filter criteria.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = data.scans.map(s => {
      const isSafe = s.prediction.includes('Safe') || s.prediction.includes('Real');
      const isSuspicious = s.prediction.includes('Suspicious');
      const tagClass = isSafe ? 'risk-tag-safe' : (isSuspicious ? 'risk-tag-medium' : 'risk-tag-high');
      const typeIcon = s.scan_type === 'url' ? 'URL' : (s.scan_type === 'email' ? 'EMAIL' : (s.scan_type === 'message' ? 'SMS' : 'SCAN'));

      return `
        <tr>
          <td><span style="font-size: 1.1rem;">${typeIcon}</span> <b style="text-transform: uppercase; font-size: 0.78rem;">${s.scan_type}</b></td>
          <td class="input-mono" style="font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${s.input_preview}
          </td>
          <td><span class="risk-tag ${tagClass}">${s.prediction}</span></td>
          <td style="font-weight: 600;">${s.confidence.toFixed(1)}%</td>
          <td style="font-weight: 800; font-family: var(--font-mono); color: ${isSafe ? 'var(--color-safe)' : (isSuspicious ? 'var(--color-suspicious)' : 'var(--color-malicious)')};">
            ${s.risk_score}
          </td>
          <td style="font-size: 0.78rem; color: var(--text-dim);">${s.created_at}</td>
          <td>
            <div style="display: flex; gap: 6px;">
              <button class="btn-cyber btn-secondary btn-sm" onclick="HistoryView.openDetailModal('${s.id}')">Inspect</button>
              <button class="btn-cyber btn-danger btn-sm" onclick="HistoryView.deleteRecord('${s.id}')">✕</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  },

  updatePagination(data) {
    const total = data.total || 0;
    const page = data.page || 1;
    const totalPages = Math.ceil(total / this.pageSize) || 1;

    const infoEl = document.getElementById('historyPaginationInfo');
    if (infoEl) {
      infoEl.innerText = `Showing Page ${page} of ${totalPages} (${total} total records)`;
    }

    const btnPrev = document.getElementById('btnPrevPage');
    const btnNext = document.getElementById('btnNextPage');

    if (btnPrev) btnPrev.disabled = page <= 1;
    if (btnNext) btnNext.disabled = page >= totalPages;
  },

  prevPage() {
    if (this.currentPage > 1) {
      this.fetchHistory(this.currentPage - 1);
    }
  },

  nextPage() {
    this.fetchHistory(this.currentPage + 1);
  },

  async deleteRecord(scanId) {
    if (!confirm('Are you sure you want to delete this scan record?')) return;

    try {
      await App.apiRequest(`/api/history/${scanId}`, { method: 'DELETE' });
      App.showToast('Record deleted successfully', 'info');
      this.fetchHistory(this.currentPage);
    } catch (err) {
      // Handled in apiRequest
    }
  },

  async confirmClearHistory() {
    if (!confirm('WARNING: This will permanently wipe all threat scan history records from the database. Proceed?')) return;

    try {
      await App.apiRequest('/api/history/clear', { method: 'POST' });
      App.showToast('Threat history wiped clean', 'info');
      this.fetchHistory(1);
      DashboardView.loadData();
    } catch (err) {
      // Handled in apiRequest
    }
  },

  async openDetailModal(scanId) {
    const modal = document.getElementById('scanDetailModal');
    const modalBody = document.getElementById('modalScanBody');
    const modalTitle = document.getElementById('modalScanTitle');

    modal.classList.add('active');
    modalBody.innerHTML = '<div style="text-align: center; padding: 32px;"><div class="cyber-spinner"></div> Loading audit record...</div>';

    try {
      const scan = await App.apiRequest(`/api/history/${scanId}`);
      modalTitle.innerText = `Threat Audit Log: ${scan.scan_type.toUpperCase()} (#${scan.id.substring(0, 8)})`;

      const isSafe = scan.prediction.includes('Safe') || scan.prediction.includes('Real');
      const isSuspicious = scan.prediction.includes('Suspicious');
      const scoreColor = isSafe ? 'var(--color-safe)' : (isSuspicious ? 'var(--color-suspicious)' : 'var(--color-malicious)');

      let indicatorsHtml = '';
      if (scan.indicators && scan.indicators.length > 0) {
        indicatorsHtml = `
          <div style="margin-top: 18px;">
            <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 10px;">Detected Threat Indicators</h4>
            <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px;">
              ${scan.indicators.map(i => `<div style="padding: 4px 0; font-size: 0.85rem;">${i}</div>`).join('')}
            </div>
          </div>
        `;
      }

      let xaiHtml = '';
      if (scan.xai_data?.highlighted_html) {
        xaiHtml = `
          <div style="margin-top: 18px;">
            <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 8px;">Explainable AI: Target Content Visualizer</h4>
            <div class="xai-preview-box">${scan.xai_data.highlighted_html}</div>
          </div>
        `;
      }

      modalBody.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-surface-elevated); padding: 16px; border-radius: var(--radius-md); border: 1px solid var(--border-color); margin-bottom: 18px;">
          <div>
            <div style="font-size: 1.2rem; font-weight: 800; color: ${scoreColor};">${scan.prediction}</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">
              Risk Level: <b>${scan.risk_level}</b> • Confidence: <b>${scan.confidence.toFixed(1)}%</b> • ${scan.created_at}
            </div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 1.8rem; font-weight: 900; font-family: var(--font-mono); color: ${scoreColor};">${scan.risk_score}</div>
            <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Cyber Risk Score</div>
          </div>
        </div>

        <div>
          <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 8px;">Raw Target Payload</h4>
          <div style="background: #0b0f17; border: 1px solid var(--border-color); padding: 12px; border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 0.82rem; max-height: 180px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;">
            ${scan.raw_input}
          </div>
        </div>

        ${indicatorsHtml}
        ${xaiHtml}
      `;
    } catch (err) {
      modalBody.innerHTML = `<div style="color: var(--color-malicious); padding: 20px;">Failed to load record details.</div>`;
    }
  },

  closeModal() {
    const modal = document.getElementById('scanDetailModal');
    if (modal) modal.classList.remove('active');
  }
};
