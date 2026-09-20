/**
 * Cyber Sentinel - Dashboard Operations & Visualizations
 */

const DashboardView = {
  trendChartInstance: null,
  severityChartInstance: null,

  async loadData() {
    try {
      const analytics = await App.apiRequest('/api/analytics');
      this.updateKPIs(analytics);
      this.renderTrendChart(analytics.daily_trends || []);
      this.renderSeverityChart(analytics.risk_level_distribution || {});
      this.renderRecentTable(analytics.recent_activity || []);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  },

  updateKPIs(data) {
    document.getElementById('kpiTotalScans').innerText = data.total_scans || 0;
    document.getElementById('kpiSafeScans').innerText = data.safe_scans || 0;
    document.getElementById('kpiSuspiciousScans').innerText = data.suspicious_scans || 0;
    document.getElementById('kpiMaliciousScans').innerText = data.malicious_scans || 0;
  },

  renderTrendChart(dailyTrends) {
    const ctx = document.getElementById('dashboardTrendChart');
    if (!ctx) return;

    if (this.trendChartInstance) {
      this.trendChartInstance.destroy();
    }

    const labels = dailyTrends.map(d => d.date);
    const safeData = dailyTrends.map(d => d.safe);
    const susData = dailyTrends.map(d => d.suspicious);
    const malData = dailyTrends.map(d => d.malicious);

    this.trendChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels.length ? labels : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        datasets: [
          {
            label: 'Safe',
            data: safeData.length ? safeData : [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            tension: 0.35,
            fill: true
          },
          {
            label: 'Suspicious',
            data: susData.length ? susData : [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            tension: 0.35,
            fill: true
          },
          {
            label: 'Malicious',
            data: malData.length ? malData : [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            tension: 0.35,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#6b7280' }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#6b7280', stepSize: 1 }
          }
        }
      }
    });
  },

  renderSeverityChart(riskDist) {
    const ctx = document.getElementById('dashboardSeverityChart');
    if (!ctx) return;

    if (this.severityChartInstance) {
      this.severityChartInstance.destroy();
    }

    const low = riskDist.LOW || 0;
    const med = riskDist.MEDIUM || 0;
    const high = riskDist.HIGH || 0;
    const crit = riskDist.CRITICAL || 0;

    const hasData = (low + med + high + crit) > 0;

    this.severityChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
        datasets: [{
          data: hasData ? [low, med, high, crit] : [1, 0, 0, 0],
          backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#ec4899'],
          borderColor: '#111827',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } }
          }
        },
        cutout: '70%'
      }
    });
  },

  renderRecentTable(scans) {
    const tbody = document.getElementById('dashboardRecentActivityTable');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 24px;">
            No threat scans recorded yet. Try running a scan or loading demo presets!
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const isSafe = s.prediction.includes('Safe') || s.prediction.includes('Real');
      const isSuspicious = s.prediction.includes('Suspicious');
      const tagClass = isSafe ? 'risk-tag-safe' : (isSuspicious ? 'risk-tag-medium' : 'risk-tag-high');
      const typeIcon = s.scan_type === 'url' ? 'URL' : (s.scan_type === 'email' ? 'EMAIL' : (s.scan_type === 'message' ? 'SMS' : 'SCAN'));

      return `
        <tr style="cursor: pointer;" onclick="HistoryView.openDetailModal('${s.id}')">
          <td><span style="font-size: 1.1rem;">${typeIcon}</span> <b style="text-transform: uppercase; font-size: 0.78rem;">${s.scan_type}</b></td>
          <td class="input-mono" style="font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${s.input_preview}
          </td>
          <td><span class="risk-tag ${tagClass}">${s.prediction}</span></td>
          <td style="font-weight: 600;">${s.confidence.toFixed(1)}%</td>
          <td style="font-weight: 800; font-family: var(--font-mono); color: ${isSafe ? 'var(--color-safe)' : (isSuspicious ? 'var(--color-suspicious)' : 'var(--color-malicious)')};">
            ${s.risk_score}
          </td>
          <td style="font-size: 0.78rem; color: var(--text-dim);">${s.created_at || 'Just now'}</td>
        </tr>
      `;
    }).join('');
  }
};
