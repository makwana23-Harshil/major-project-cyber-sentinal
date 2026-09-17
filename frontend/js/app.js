/**
 * Cyber Sentinel - Core Application Navigation & API Client
 */

const App = {
  currentView: 'dashboard',

  init() {
    this.setupNavigation();
    this.loadInitialView();
  },

  setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetView = link.getAttribute('data-view');
        this.navigateTo(targetView);
      });
    });
  },

  navigateTo(viewName) {
    this.currentView = viewName;

    // Update active class on nav links
    document.querySelectorAll('.nav-link').forEach(link => {
      if (link.getAttribute('data-view') === viewName) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Update active view panel
    document.querySelectorAll('.view-panel').forEach(panel => {
      panel.classList.remove('active');
    });

    const targetPanel = document.getElementById(`view-${viewName}`);
    if (targetPanel) {
      targetPanel.classList.add('active');
    }

    // Update topbar title
    const titleMap = {
      'dashboard': 'Security Operations Dashboard',
      'url-scanner': 'Deep URL Phishing Scanner',
      'email-scanner': 'Email & Attachment Threat Scanner',
      'message-scanner': 'Smishing & Instant Message Analyzer',
      'threat-history': 'Threat History & Audit Log',
      'analytics': 'Threat Intelligence & Attack Vectors',
      'model-metrics': 'Explainable AI & Model Performance',
      'demo-mode': 'Interactive Demo Test Presets',
      'about-arch': 'System Architecture & Documentation'
    };
    const titleEl = document.getElementById('pageTitle');
    if (titleEl) {
      titleEl.innerText = titleMap[viewName] || 'Cyber Sentinel';
    }

    // Trigger view-specific data refresh
    if (viewName === 'dashboard') {
      DashboardView.loadData();
    } else if (viewName === 'threat-history') {
      HistoryView.fetchHistory(1);
    } else if (viewName === 'analytics') {
      AnalyticsView.loadAnalytics();
    } else if (viewName === 'model-metrics') {
      ExplainabilityView.loadMetrics();
    } else if (viewName === 'demo-mode') {
      DemoView.loadDemoSamples();
    }
  },

  loadInitialView() {
    this.navigateTo('dashboard');
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const icon = type === 'success' ? '✅' : (type === 'error' ? '🚨' : 'ℹ️');
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  async apiRequest(endpoint, options = {}) {
    try {
      const response = await fetch(endpoint, {
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {})
        },
        ...options
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server error (${response.status})`);
      }

      return await response.json();
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      this.showToast(err.message || 'An error occurred while contacting the server', 'error');
      throw err;
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
