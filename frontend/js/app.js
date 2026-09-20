/**
 * Cyber Sentinel - Core Application Navigation & API Client
 *
 * IMPORTANT:
 * This file handles:
 * 1. SPA navigation
 * 2. API requests
 *
 * User authentication:
 * - User pages use Utoken
 * - Admin pages use Atoken
 *
 * Do NOT put dashboard-specific functions here.
 */

const App = {
  currentView: 'dashboard',

  // ==========================================
  // INITIALIZATION
  // ==========================================

  init() {
    this.setupNavigation();
    this.loadInitialView();
  },


  // ==========================================
  // NAVIGATION
  // ==========================================

  setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();

        const targetView = link.getAttribute('data-view');

        if (targetView) {
          this.navigateTo(targetView);
        }
      });
    });
  },


  navigateTo(viewName) {
    this.currentView = viewName;

    // ------------------------------------------
    // Update active navigation link
    // ------------------------------------------

    document.querySelectorAll('.nav-link').forEach(link => {
      if (link.getAttribute('data-view') === viewName) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });


    // ------------------------------------------
    // Update active view panel
    // ------------------------------------------

    document.querySelectorAll('.view-panel').forEach(panel => {
      panel.classList.remove('active');
    });

    const targetPanel = document.getElementById(`view-${viewName}`);

    if (targetPanel) {
      targetPanel.classList.add('active');
    }


    // ------------------------------------------
    // Update page title
    // ------------------------------------------

    const titleMap = {
      dashboard: 'Security Operations Dashboard',
      'url-scanner': 'Deep URL Phishing Scanner',
      'email-scanner': 'Email & Attachment Threat Scanner',
      'message-scanner': 'Smishing & Instant Message Analyzer',
      'threat-history': 'Threat History & Audit Log',
      analytics: 'Threat Intelligence & Attack Vectors',
      'model-metrics': 'Explainable AI & Model Performance',
      'demo-mode': 'Interactive Demo Test Presets',
      'about-arch': 'System Architecture & Documentation'
    };

    const titleEl = document.getElementById('pageTitle');

    if (titleEl) {
      titleEl.innerText =
        titleMap[viewName] || 'Cyber Sentinel';
    }


    // ------------------------------------------
    // Load view-specific data
    // ------------------------------------------

    if (viewName === 'dashboard') {

      if (typeof DashboardView !== 'undefined') {
        DashboardView.loadData();
      }

    } else if (viewName === 'threat-history') {

      if (typeof HistoryView !== 'undefined') {
        HistoryView.fetchHistory(1);
      }

    } else if (viewName === 'analytics') {

      if (typeof AnalyticsView !== 'undefined') {
        AnalyticsView.loadAnalytics();
      }

    } else if (viewName === 'model-metrics') {

      if (typeof ExplainabilityView !== 'undefined') {
        ExplainabilityView.loadMetrics();
      }

    } else if (viewName === 'demo-mode') {

      if (typeof DemoView !== 'undefined') {
        DemoView.loadDemoSamples();
      }
    }
  },


  // ==========================================
  // INITIAL VIEW
  // ==========================================

  loadInitialView() {
    this.navigateTo('dashboard');
  },


  // ==========================================
  // TOAST
  // ==========================================

  showToast(message, type = 'info') {

    const container =
      document.getElementById('toastContainer');

    if (!container) {
      return;
    }

    const toast = document.createElement('div');

    toast.className = `toast toast-${type}`;

    const icon =
      type === 'success'
        ? '<i class="fas fa-check"></i>'
        : type === 'error'
          ? '<i class="fas fa-triangle-exclamation"></i>'
          : '<i class="fas fa-circle-info"></i>';

    toast.innerHTML =
      `<span>${icon}</span> <span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {

      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';

      setTimeout(() => {
        toast.remove();
      }, 300);

    }, 4000);
  },


  // ==========================================
  // API REQUEST
  // ==========================================

  async apiRequest(endpoint, options = {}) {

    try {

      /*
       * USER DASHBOARD
       *
       * All /api/user/... requests must use Utoken.
       */

      const isUserAPI =
        endpoint.startsWith('/api/user/') ||
        endpoint.startsWith('/api/analytics') ||
        endpoint.startsWith('/api/scan');


      /*
       * ADMIN API
       *
       * All /api/admin/... requests must use Atoken.
       */

      const isAdminAPI =
        endpoint.startsWith('/api/admin/');


      let token = null;

      if (isAdminAPI) {

        token = localStorage.getItem('Atoken');

      } else if (isUserAPI) {

        token = localStorage.getItem('Utoken');

      }


      // ------------------------------------------
      // Build headers
      // ------------------------------------------

      const headers = {
        'Content-Type': 'application/json'
      };


      if (token) {

        headers['Authorization'] =
          'Bearer ' + token;

      }


      // Allow custom headers to override defaults
      Object.assign(headers, options.headers || {});


      // ------------------------------------------
      // Make request
      // ------------------------------------------

      const response = await fetch(endpoint, {
        ...options,
        headers
      });


      // ------------------------------------------
      // Handle authentication errors
      // ------------------------------------------

      if (response.status === 401) {

        console.error(
          `Unauthorized API request: ${endpoint}`
        );


        if (isAdminAPI) {

          localStorage.removeItem('Atoken');
          localStorage.removeItem('admin_data');

          window.location.href = 'login.html';

          return;

        }


        if (isUserAPI) {

          localStorage.removeItem('Utoken');
          localStorage.removeItem('user_data');

          window.location.href = 'login.html';

          return;

        }
      }


      // ------------------------------------------
      // Handle other server errors
      // ------------------------------------------

      if (!response.ok) {

        const errorData =
          await response.json().catch(() => ({}));

        throw new Error(
          errorData.message ||
          errorData.detail ||
          `Server error (${response.status})`
        );
      }


      // ------------------------------------------
      // Return JSON
      // ------------------------------------------

      return await response.json();

    } catch (err) {

      console.error(
        `API Error on ${endpoint}:`,
        err
      );

      this.showToast(
        err.message ||
        'An error occurred while contacting the server',
        'error'
      );

      throw err;
    }
  }
};


// ==========================================
// START APPLICATION
// ==========================================

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});