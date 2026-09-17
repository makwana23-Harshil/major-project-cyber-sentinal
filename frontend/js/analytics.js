/**
 * Cyber Sentinel - Threat Analytics & Attack Vector Intelligence
 */

const AnalyticsView = {
  topIndicatorsChartInstance: null,
  vectorChartInstance: null,
  weeklyTrendsChartInstance: null,

  async loadAnalytics() {
    try {
      const data = await App.apiRequest('/api/analytics');
      this.updateKPIs(data);
      this.renderTopIndicatorsChart(data.top_indicators || []);
      this.renderVectorChart(data.vector_distribution || {});
      this.renderWeeklyTrendsChart(data.daily_trends || []);
    } catch (err) {
      console.error('Failed to load analytics data:', err);
    }
  },

  updateKPIs(data) {
    const rateEl = document.getElementById('analyticsDetectionRate');
    const riskEl = document.getElementById('analyticsAvgRisk');

    if (rateEl) rateEl.innerText = `${data.detection_rate || 0}%`;
    if (riskEl) riskEl.innerText = `${data.avg_risk_score || 0} / 100`;
  },

  renderTopIndicatorsChart(indicators) {
    const ctx = document.getElementById('analyticsTopIndicatorsChart');
    if (!ctx) return;

    if (this.topIndicatorsChartInstance) {
      this.topIndicatorsChartInstance.destroy();
    }

    const labels = indicators.map(i => i.indicator);
    const counts = indicators.map(i => i.count);

    this.topIndicatorsChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels.length ? labels : ['No threat indicators detected yet'],
        datasets: [{
          label: 'Triggered Count',
          data: counts.length ? counts : [0],
          backgroundColor: '#06b6d4',
          borderRadius: 6
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#6b7280', stepSize: 1 }
          },
          y: {
            grid: { display: false },
            ticks: { color: '#9ca3af', font: { size: 11 } }
          }
        }
      }
    });
  },

  renderVectorChart(vectorDist) {
    const ctx = document.getElementById('analyticsVectorChart');
    if (!ctx) return;

    if (this.vectorChartInstance) {
      this.vectorChartInstance.destroy();
    }

    const labels = ['URLs', 'Emails', 'Messages / SMS', 'Raw Text'];
    const dataVals = [
      vectorDist.url || 0,
      vectorDist.email || 0,
      vectorDist.message || 0,
      vectorDist.text || 0
    ];

    const hasData = dataVals.reduce((a, b) => a + b, 0) > 0;

    this.vectorChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: hasData ? dataVals : [1, 1, 1, 1],
          backgroundColor: ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899'],
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
            labels: { color: '#9ca3af', font: { size: 11 } }
          }
        },
        cutout: '65%'
      }
    });
  },

  renderWeeklyTrendsChart(trends) {
    const ctx = document.getElementById('analyticsWeeklyTrendsChart');
    if (!ctx) return;

    if (this.weeklyTrendsChartInstance) {
      this.weeklyTrendsChartInstance.destroy();
    }

    const labels = trends.map(t => t.date);
    const safeData = trends.map(t => t.safe);
    const susData = trends.map(t => t.suspicious);
    const malData = trends.map(t => t.malicious);

    this.weeklyTrendsChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels.length ? labels : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        datasets: [
          {
            label: 'Safe',
            data: safeData.length ? safeData : [0, 0, 0, 0, 0, 0, 0],
            backgroundColor: '#10b981'
          },
          {
            label: 'Suspicious',
            data: susData.length ? susData : [0, 0, 0, 0, 0, 0, 0],
            backgroundColor: '#f59e0b'
          },
          {
            label: 'Malicious',
            data: malData.length ? malData : [0, 0, 0, 0, 0, 0, 0],
            backgroundColor: '#ef4444'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: '#9ca3af', font: { size: 11 } }
          }
        },
        scales: {
          x: {
            stacked: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#6b7280' }
          },
          y: {
            stacked: true,
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#6b7280', stepSize: 1 }
          }
        }
      }
    });
  }
};
