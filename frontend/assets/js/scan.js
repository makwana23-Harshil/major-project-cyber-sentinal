/* =============================================
   CyberSentinel Pro — Scan JS
   Handles all 4 scan panels + result rendering
============================================= */

// ── Auth guard ──
document.addEventListener('DOMContentLoaded', () => {
  if (!requireAuth()) return;
});

// ── Panel switcher ──
function switchPanel(name) {
  document.querySelectorAll('.scan-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.scan-nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  document.getElementById('nav-' + name).classList.add('active');
  // Clear previous results
  ['sms','email-address','email-body','url'].forEach(t => {
    const el = document.getElementById('result-' + t);
    if (el) { el.classList.add('hidden'); el.innerHTML = ''; }
  });
}

// ── Loading overlay ──
let loadingStepTimer;
function showLoading(type) {
  document.getElementById('scan-loading').classList.remove('hidden');
  const titles = {
    'sms': 'Analyzing SMS Message...',
    'email-address': 'Validating Email Address...',
    'email-body': 'Scanning Email Body...',
    'url': 'Deep Inspecting URL...'
  };
  document.getElementById('scan-loading-title').textContent = titles[type] || 'Analyzing...';

  // Animate steps
  const steps = document.querySelectorAll('.scan-step');
  steps.forEach(s => { s.classList.remove('active','done'); });
  let idx = 0;
  loadingStepTimer = setInterval(() => {
    if (idx > 0) steps[idx-1].classList.remove('active');
    if (idx < steps.length) {
      if (idx > 0) steps[idx-1].classList.add('done');
      steps[idx].classList.add('active');
      idx++;
    }
  }, 900);
}

function hideLoading() {
  clearInterval(loadingStepTimer);
  document.getElementById('scan-loading').classList.add('hidden');
  document.querySelectorAll('.scan-step').forEach(s => s.classList.remove('active','done'));
}

// ── Main scan runner ──
async function runScan(type) {
  if (!requireAuth()) return;
  const resultEl = document.getElementById('result-' + type);

  // Gather input
  let payload = {};
  let inputVal = '';

  if (type === 'sms') {
    inputVal = (document.getElementById('sms-input').value || '').trim();
    if (!inputVal) { showToast('Please enter an SMS message', 'warning'); return; }

    payload = {input_text: inputVal,inspect_links: document.getElementById('sms-inspect').checked};

  } else if (type === 'email-address') {
    inputVal = (document.getElementById('email-addr-input').value || '').trim();
    if (!inputVal) { showToast('Please enter an email address', 'warning'); return; }
    payload = { email: inputVal };
  } else if (type === 'email-body') {
    inputVal = (document.getElementById('email-body-input').value || '').trim();
    if (!inputVal) { showToast('Please enter email body content', 'warning'); return; }
    payload = { body: inputVal, inspect_links: document.getElementById('email-body-inspect').checked };
  } else if (type === 'url') {
    inputVal = (document.getElementById('url-input').value || '').trim();
    if (!inputVal) { showToast('Please enter a URL', 'warning'); return; }
    payload = { url: inputVal, deep_inspect: document.getElementById('url-inspect').checked };
  }

  showLoading(type);
  resultEl.classList.add('hidden');
  resultEl.innerHTML = '';

  const endpointMap = {
    'sms': '/api/scan/sms',
    'email-address': '/api/scan/email-address',
    'email-body': '/api/scan/email-body',
    'url': '/api/scan/url'
  };

  try {
    const res = await API.post(endpointMap[type], payload);
    const data = await res.json();
    hideLoading();

    if (!res.ok || !data.success) {
      if (res.status === 503) {
        resultEl.innerHTML = `<div class="alert alert-warning"><i class="fas fa-exclamation-triangle"></i> <strong>Models not trained yet.</strong> Please wait a moment and refresh — the backend is training ML models on first startup.</div>`;
      } else {
        resultEl.innerHTML = `<div class="alert alert-danger"><i class="fas fa-times-circle"></i> ${data.message || 'Analysis failed'}</div>`;
      }
      resultEl.classList.remove('hidden');
      return;
    }

    const result = data.result;
    resultEl.innerHTML = buildResultHTML(type, result);
    resultEl.classList.remove('hidden');
    resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Animate risk bar
    setTimeout(() => {
      const bar = resultEl.querySelector('.risk-bar-fill');
      if (bar) {
        const score = result.risk_score || 0;
        bar.style.width = score + '%';
        bar.style.background = score >= 65 ? '#FF4757' : score >= 35 ? '#FFA502' : '#2ED573';
      }
    }, 200);

  } catch (err) {
    hideLoading();
    resultEl.innerHTML = `<div class="alert alert-danger"><i class="fas fa-wifi"></i> Cannot connect to backend. Is the server running at http://127.0.0.1:5000?</div>`;
    resultEl.classList.remove('hidden');
  }
}

// ── Result HTML Builders ──
function getVerdictStyle(verdict) {
  const v = (verdict || '').toUpperCase();
  const isDanger = ['DANGEROUS','PHISHING','SPAM','FAKE','DISPOSABLE','INVALID','NON-EXISTENT','MALICIOUS'].includes(v);
  const isWarning = ['SUSPICIOUS'].includes(v);
  const isSafe = ['SAFE','LEGITIMATE','VALID','HAM'].includes(v);
  return {
    icon: isDanger ? 'DANGER' : isWarning ? 'WARNING' : 'SAFE',
    iconClass: isDanger ? 'danger' : isWarning ? 'warning' : 'safe',
    badgeClass: isDanger ? 'badge-dangerous' : isWarning ? 'badge-suspicious' : 'badge-safe',
    color: isDanger ? 'var(--danger)' : isWarning ? 'var(--warning)' : 'var(--success)'
  };
}

function buildEvidenceHTML(evidenceList) {
  if (!evidenceList || !evidenceList.length) return '';
  return `
    <div class="evidence-section">
      <h4 style="font-size:0.88rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-light);margin-bottom:0.5rem;">Analysis Evidence</h4>
      <div class="evidence-list">
        ${evidenceList.map(e => `<div class="evidence-item">${e}</div>`).join('')}
      </div>
    </div>`;
}

function buildLinkInspectionHTML(links) {
  if (!links || !links.length) return '';
  return `
    <div class="links-section">
      <h4 style="font-size:0.88rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-light);margin-bottom:1rem;">Real-World Link Inspection & Content Analysis (${links.length})</h4>
      ${links.map(link => {
        const s = getVerdictStyle(link.verdict);
        const llm = link.llm_analysis;
        return `
        <div class="link-inspection-card">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
            <div style="font-weight:700;font-size:0.95rem;">${s.icon} ${link.verdict || 'UNKNOWN'}</div>
            <span class="badge badge-${(link.verdict||'').toLowerCase()}" style="font-size:0.75rem;">Risk: ${link.risk_score || 0}/100</span>
          </div>
          <div class="link-url"><strong>Target:</strong> ${link.url}</div>
          ${link.final_url && link.final_url !== link.url ? `<div class="link-url" style="color:var(--blue-dark);"><strong>→ Destination:</strong> ${link.final_url}</div>` : ''}
          ${link.page_title ? `<div style="font-size:0.82rem;color:var(--text-secondary);margin:0.25rem 0 0.5rem;"><strong>Page Title:</strong> "${link.page_title}"</div>` : ''}

          <div class="link-meta">
            ${link.dns_exists !== undefined ? `<span class="link-tag ${link.dns_exists ? 'green' : 'red'}">${link.dns_exists ? 'DNS Active' : 'Non-Existent Domain'}</span>` : ''}
            <span class="link-tag ${link.ssl_valid ? 'green' : 'red'}">${link.ssl_valid ? 'SSL Secure' : 'No Valid SSL'}</span>
            ${link.is_reachable !== undefined ? `<span class="link-tag ${link.is_reachable ? 'green' : 'red'}">${link.is_reachable ? 'Web Server Active' : 'Server Unreachable'}</span>` : ''}
            ${link.http_status ? `<span class="link-tag ${link.http_status < 400 ? 'green' : 'red'}">HTTP ${link.http_status}</span>` : ''}
            ${link.redirect_count > 0 ? `<span class="link-tag orange">↩ ${link.redirect_count} Redirect(s)</span>` : ''}
            ${link.safe_browsing_flag ? `<span class="link-tag red">Google Safe Browsing Flagged</span>` : ''}
            ${link.virustotal_score ? `<span class="link-tag ${link.virustotal_score.startsWith('0') ? 'green' : 'red'}">VT: ${link.virustotal_score}</span>` : ''}
          </div>

          ${llm && llm.enabled ? `
            <div style="margin-top:12px;padding:12px 14px;background:linear-gradient(135deg,rgba(0,212,255,0.06),rgba(123,94,167,0.08));border:1px solid rgba(0,212,255,0.25);border-radius:8px;">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;flex-wrap:wrap;gap:6px;">
                <span style="font-weight:700;font-size:0.85rem;color:var(--navy);"><i class="fas fa-brain" style="color:var(--blue);"></i> AI Real-World Existence & Content Analysis</span>
                <span class="badge ${llm.real_world_exists ? 'badge-safe' : 'badge-dangerous'}">${llm.real_world_exists ? 'Real-World Entity: YES' : 'Real-World Entity: NO (Fake/Dead)'}</span>
              </div>
              <div style="font-size:0.85rem;font-weight:700;color:var(--navy);margin-bottom:4px;">${llm.site_identity || ''}</div>
              <div style="font-size:0.82rem;color:var(--text-secondary);line-height:1.5;">${llm.safety_summary || ''}</div>
              ${llm.key_findings && llm.key_findings.length ? `
                <ul style="margin-top:6px;padding-left:18px;font-size:0.78rem;color:var(--text-secondary);line-height:1.5;">
                  ${llm.key_findings.map(f => `<li>${f}</li>`).join('')}
                </ul>` : ''}
            </div>` : ''}

          ${link.risk_evidence && link.risk_evidence.length ? `
            <div style="margin-top:0.75rem;display:flex;flex-direction:column;gap:4px;">
              ${link.risk_evidence.slice(0,6).map(e => `<div style="font-size:0.78rem;color:var(--text-secondary);padding:5px 8px;background:var(--bg-card);border-radius:4px;">${e}</div>`).join('')}
            </div>` : ''}
        </div>`;
      }).join('')}
    </div>`;
}

function buildResultHTML(type, result) {
  const s = getVerdictStyle(result.verdict);
  const riskScore = result.risk_score || 0;
  const conf = result.confidence ? Math.round(result.confidence * 100) : 0;

  let statsHTML = '';
  let extraHTML = '';
  let linksHTML = '';
  let evidenceArr = [];

  // Collect evidence
  evidenceArr = result.risk_evidence || result.analysis_notes || result.url_features || [];

  if (type === 'sms') {
    statsHTML = `
      <div class="result-stats">
        <div class="result-stat"><div class="val" style="color:${s.color}">${result.ml_prediction || result.verdict}</div><div class="lbl">ML Prediction</div></div>
        <div class="result-stat"><div class="val">${Math.round((result.spam_probability||0)*100)}%</div><div class="lbl">Spam Prob.</div></div>
        <div class="result-stat"><div class="val">${result.url_count || 0}</div><div class="lbl">URLs Found</div></div>
        <div class="result-stat"><div class="val">${riskScore}/100</div><div class="lbl">Risk Score</div></div>
      </div>`;
    linksHTML = buildLinkInspectionHTML(result.link_inspections);
    if (result.analysis_notes && result.analysis_notes.length) evidenceArr = result.analysis_notes;
  } else if (type === 'email-address') {
    statsHTML = `
      <div class="result-stats">
        <div class="result-stat"><div class="val" style="color:${result.is_valid_syntax ? 'var(--success)':'var(--danger)'}">${result.is_valid_syntax ? 'Valid':'Invalid'}</div><div class="lbl">Syntax</div></div>
        <div class="result-stat"><div class="val" style="color:${result.is_disposable ? 'var(--danger)':'var(--success)'}">${result.is_disposable ? 'Yes':'No'}</div><div class="lbl">Disposable</div></div>
        <div class="result-stat"><div class="val" style="color:${result.has_mx_records ? 'var(--success)':'var(--danger)'}">${result.has_mx_records ? 'Found':'None'}</div><div class="lbl">MX Records</div></div>
        <div class="result-stat"><div class="val">${result.domain_age && result.domain_age.age_days != null ? result.domain_age.age_days + 'd' : 'N/A'}</div><div class="lbl">Domain Age</div></div>
      </div>`;
    if (result.mx_records && result.mx_records.length) {
      extraHTML = `<div class="evidence-section"><h4 style="font-size:0.88rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-light);margin-bottom:0.5rem;">Mail Servers</h4>${result.mx_records.map(mx => `<div class="evidence-item" style="font-family:monospace;font-size:0.8rem;">${mx}</div>`).join('')}</div>`;
    }
    evidenceArr = result.risk_evidence || [];
  } else if (type === 'email-body') {
    statsHTML = `
      <div class="result-stats">
        <div class="result-stat"><div class="val" style="color:${s.color}">${result.ml_prediction || result.verdict}</div><div class="lbl">ML Prediction</div></div>
        <div class="result-stat"><div class="val">${Math.round((result.spam_probability||0)*100)}%</div><div class="lbl">Spam Prob.</div></div>
        <div class="result-stat"><div class="val">${result.url_count || 0}</div><div class="lbl">Links Found</div></div>
        <div class="result-stat"><div class="val">${riskScore}/100</div><div class="lbl">Risk Score</div></div>
      </div>`;
    linksHTML = buildLinkInspectionHTML(result.link_inspections);
    evidenceArr = result.risk_evidence || [];
  } else if (type === 'url') {
    const isThreat = ['DANGEROUS','PHISHING','FAKE','NON-EXISTENT','MALICIOUS'].includes((result.verdict||'').toUpperCase());
    const threatScore = Math.round((result.phishing_probability || (result.risk_score ? result.risk_score/100 : 0)) * 100);
    statsHTML = `
      <div class="result-stats">
        <div class="result-stat"><div class="val" style="color:${s.color}">${result.verdict}</div><div class="lbl">Unified Verdict</div></div>
        <div class="result-stat"><div class="val" style="color:${isThreat ? 'var(--danger)' : 'var(--success)'}">${threatScore}%</div><div class="lbl">Threat / Phish Prob.</div></div>
        <div class="result-stat"><div class="val">${result.deep_inspection ? (result.deep_inspection.redirect_count||0) : 0}</div><div class="lbl">Redirects</div></div>
        <div class="result-stat"><div class="val">${riskScore}/100</div><div class="lbl">Risk Score</div></div>
      </div>`;
    if (result.deep_inspection) linksHTML = buildLinkInspectionHTML([result.deep_inspection]);
    const urlFeat = result.url_features || [];
    const deepEv = result.deep_inspection ? (result.deep_inspection.risk_evidence || []) : [];
    evidenceArr = [...urlFeat, ...deepEv];
  }

  return `
    <div class="result-panel verdict-${s.iconClass}">
      <div class="result-header">
        <div class="verdict-display">
          <div class="verdict-icon ${s.iconClass}" aria-label="${s.iconClass} status">${s.icon}</div>
          <div class="verdict-text">
            <h3 class="verdict-heading"><span class="badge ${s.badgeClass}">${result.verdict}</span></h3>
            <div class="verdict-sub"><span>Confidence <strong>${conf}%</strong></span><span class="verdict-divider">|</span><span>Risk Score <strong>${riskScore}/100</strong></span></div>
          </div>
        </div>
        <div style="font-size:0.8rem;color:var(--text-light);">${new Date().toLocaleTimeString()}</div>
      </div>

      <div class="risk-section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
          <span style="font-size:0.85rem;font-weight:600;">Risk Score</span>
          <span style="font-size:0.85rem;font-weight:700;color:${riskScore>=65?'var(--danger)':riskScore>=35?'var(--warning)':'var(--success)'}">${riskScore}/100</span>
        </div>
        <div class="risk-bar-bg">
          <div class="risk-bar-fill" style="width:0%;background:${riskScore>=65?'var(--danger)':riskScore>=35?'var(--warning)':'var(--success)'};"></div>
        </div>
        <div class="risk-pct" style="color:${riskScore>=65?'var(--danger)':riskScore>=35?'var(--warning)':'var(--success)'}">
          ${riskScore < 35 ? 'Low Risk' : riskScore < 65 ? 'Moderate Risk' : 'High Risk'}
        </div>
        <div style="clear:both;"></div>
      </div>

      <div style="padding:1.25rem 1.75rem;border-bottom:1px solid var(--border-soft);">
        ${statsHTML}
      </div>

      ${buildEvidenceHTML(evidenceArr)}
      ${extraHTML}
      ${linksHTML}

      <div style="padding:1rem 1.75rem;display:flex;gap:0.75rem;flex-wrap:wrap;">
        <button class="btn btn-outline btn-sm" onclick="window.location.href='history.html'"><i class="fas fa-history"></i> View History</button>
        <button class="btn btn-outline btn-sm" onclick="copyResult('${result.verdict}', ${riskScore})"><i class="fas fa-copy"></i> Copy Result</button>
      </div>
    </div>`;
}

function copyResult(verdict, riskScore) {
  const text = `CyberSentinel Pro Result:\nVerdict: ${verdict}\nRisk Score: ${riskScore}/100\nScanned at: ${new Date().toLocaleString()}`;
  navigator.clipboard.writeText(text).then(() => showToast('Result copied to clipboard', 'success'));
}
