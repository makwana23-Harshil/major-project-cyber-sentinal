/* =============================================
   CyberSentinel Pro — Charts JS (Chart.js wrappers)
============================================= */

const ChartDefaults = {
  fontFamily: "'Inter', sans-serif",
  color: '#5A6275'
};

Chart.defaults.font.family = ChartDefaults.fontFamily;
Chart.defaults.color = ChartDefaults.color;

const activeCharts = {};

function destroyChart(id) {
  if (activeCharts[id]) { activeCharts[id].destroy(); delete activeCharts[id]; }
}

// ── Donut Chart ──
function renderDonut(canvasId, { labels, data, colors }) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const total = data.reduce((a, b) => a + b, 0);
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors,
        borderColor: '#fff',
        borderWidth: 3,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { padding: 16, usePointStyle: true, pointStyle: 'circle', font: { size: 11 } }
        },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const val = ctx.raw;
              const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0.0';
              return `  ${ctx.label}: ${val} (${pct}%)`;
            }
          }
        }
      },
      animation: { animateScale: true, animateRotate: true, duration: 900 }
    }
  });
}

// ── Line Chart ──
function renderLine(canvasId, { labels, data, label = 'Count', color = '#00D4FF' }) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label,
        data,
        borderColor: color,
        backgroundColor: `${color}18`,
        borderWidth: 2.5,
        pointRadius: 3,
        pointHoverRadius: 5,
        pointBackgroundColor: color,
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: {
          grid: { color: 'rgba(0,0,0,0.04)' },
          ticks: { maxTicksLimit: 10, font: { size: 10 } }
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(0,0,0,0.04)' },
          ticks: { stepSize: 1, font: { size: 10 } }
        }
      },
      animation: { duration: 1000, easing: 'easeInOutQuart' }
    }
  });
}

// ── Multi-line Chart ──
function renderMultiLine(canvasId, { labels, datasets }) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const colors = ['#00D4FF', '#FF4757', '#2ED573', '#FFA502', '#7B5EA7'];
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: datasets.map((ds, i) => ({
        label: ds.label,
        data: ds.data,
        borderColor: colors[i % colors.length],
        backgroundColor: `${colors[i % colors.length]}12`,
        borderWidth: 2,
        pointRadius: 3,
        fill: false,
        tension: 0.4
      }))
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top', labels: { usePointStyle: true, pointStyle: 'circle', font: { size: 11 } } },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: { grid: { color: 'rgba(0,0,0,0.04)' }, ticks: { maxTicksLimit: 8, font: { size: 10 } } },
        y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.04)' }, ticks: { stepSize: 1, font: { size: 10 } } }
      },
      animation: { duration: 1000 }
    }
  });
}

// ── Bar Chart ──
function renderBar(canvasId, { labels, data, label = 'Count', color = '#0A0E27', horizontal = false }) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  activeCharts[canvasId] = new Chart(ctx, {
    type: horizontal ? 'bar' : 'bar',
    data: {
      labels,
      datasets: [{
        label,
        data,
        backgroundColor: Array.isArray(color) ? color : `${color}CC`,
        borderColor: Array.isArray(color) ? color : color,
        borderWidth: 1,
        borderRadius: 6,
        borderSkipped: false
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: horizontal ? 'y' : 'x',
      plugins: {
        legend: { display: false },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: { grid: { color: 'rgba(0,0,0,0.04)' }, ticks: { font: { size: 10 } } },
        y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.04)' }, ticks: { stepSize: 1, font: { size: 10 } } }
      },
      animation: { duration: 900, easing: 'easeInOutQuart' }
    }
  });
}

// ── Stacked Bar Chart ──
function renderStackedBar(canvasId, { labels, datasets }) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const colors = ['#FF4757', '#FFA502', '#2ED573', '#00D4FF'];
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: datasets.map((ds, i) => ({
        label: ds.label,
        data: ds.data,
        backgroundColor: `${colors[i % colors.length]}CC`,
        borderRadius: i === datasets.length - 1 ? 6 : 0,
        borderSkipped: false
      }))
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top', labels: { usePointStyle: true, font: { size: 11 } } }
      },
      scales: {
        x: { stacked: true, grid: { display: false }, ticks: { font: { size: 10 } } },
        y: { stacked: true, beginAtZero: true, grid: { color: 'rgba(0,0,0,0.04)' } }
      },
      animation: { duration: 900 }
    }
  });
}

// ── Hourly Heatmap (Bar) ──
function renderHourlyBar(canvasId, hourlyData) {
  const hours = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  const data = hours.map((_, i) => hourlyData[String(i).padStart(2, '0')] || 0);
  const maxVal = Math.max(...data, 1);
  const colors = data.map(v => {
    const intensity = v / maxVal;
    const r = Math.round(10 + 0 * intensity);
    const g = Math.round(14 + 198 * intensity);
    const b = Math.round(39 + 216 * intensity);
    return `rgba(${r},${g},${b},${0.4 + 0.6 * intensity})`;
  });
  renderBar(canvasId, { labels: hours, data, label: 'Scans', color: colors });
}
