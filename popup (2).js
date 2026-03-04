// Enhanced Popup script for PhishScan extension with VirusTotal integration

// Multilingual translation system (Hindi, Gujarati, English)
const translations = {
  en: {
    detectionOff: 'Detection is OFF',
    scanning: '🔍 Scanning for malicious URLs...',
    scanTimeout: '⚠️ Scan is taking too long - results may be partial',
    rateLimited: '⚠️ API rate limit reached - some URLs may not be checked',
    noUrlsFound: '✅ No URLs found on this page',
    pageSafe: (count) => `✅ Page appears safe (${count} URLs scanned)`,
    threatsDetected: (count) => `⚠️ ${count} malicious URL${count > 1 ? 's' : ''} detected!`,
    urlsScanned: 'URLs Scanned',
    threatsFound: 'Threats Found',
    verifiedSafe: 'Verified Safe',
    detectedThreats: '⚠️ Detected Threats',
    recentScans: '📊 Recent Scans',
    refreshScan: '🔄 Refresh Scan',
    viewDetails: '📋 View Details',
    malicious: 'Malicious',
    safe: 'Safe'
  },
  hi: {
    detectionOff: 'डिटेक्शन बंद है',
    scanning: '🔍 दुर्भावनापूर्ण URL स्कैन किया जा रहा है...',
    scanTimeout: '⚠️ स्कैन बहुत लंबा हो रहा है - परिणाम आंशिक हो सकते हैं',
    rateLimited: '⚠️ API दर सीमा पहुंच गई - कुछ URL जांचे नहीं जा सकते',
    noUrlsFound: '✅ इस पृष्ठ पर कोई URL नहीं मिला',
    pageSafe: (count) => `✅ पृष्ठ सुरक्षित लगता है (${count} URL स्कैन किए गए)`,
    threatsDetected: (count) => `⚠️ ${count} दुर्भावनापूर्ण URL${count > 1 ? ' पाए गए' : ' पाया गया'}!`,
    urlsScanned: 'URL स्कैन किए गए',
    threatsFound: 'खतरे मिले',
    verifiedSafe: 'सत्यापित सुरक्षित',
    detectedThreats: '⚠️ पाए गए खतरे',
    recentScans: '📊 हाल की स्कैन',
    refreshScan: '🔄 स्कैन रीफ्रेश करें',
    viewDetails: '📋 विवरण देखें',
    malicious: 'दुर्भावनापूर्ण',
    safe: 'सुरक्षित'
  },
  gu: {
    detectionOff: 'ડિટેક્શન બંધ છે',
    scanning: '🔍 દુર્ભાવનાપૂર્ણ URL સ્કેન કરવામાં આવી રહ્યું છે...',
    scanTimeout: '⚠️ સ્કેન ખૂબ લાંબું થઈ રહ્યું છે - પરિણામો આંશિક હોઈ શકે છે',
    rateLimited: '⚠️ API દર મર્યાદા પહોંચી ગઈ - કેટલાક URL તપાસી શકાતા નથી',
    noUrlsFound: '✅ આ પૃષ્ઠ પર કોઈ URL મળ્યું નથી',
    pageSafe: (count) => `✅ પૃષ્ઠ સુરક્ષિત લાગે છે (${count} URL સ્કેન કરવામાં આવ્યા)`,
    threatsDetected: (count) => `⚠️ ${count} દુર્ભાવનાપૂર્ણ URL${count > 1 ? ' મળ્યા' : ' મળ્યું'}!`,
    urlsScanned: 'URL સ્કેન કરવામાં આવ્યા',
    threatsFound: 'ખતરા મળ્યા',
    verifiedSafe: 'ચકાસાયેલ સુરક્ષિત',
    detectedThreats: '⚠️ મળેલા ખતરા',
    recentScans: '📊 તાજેતરની સ્કેન',
    refreshScan: '🔄 સ્કેન રીફ્રેશ કરો',
    viewDetails: '📋 વિગતો જુઓ',
    malicious: 'દુર્ભાવનાપૂર્ણ',
    safe: 'સુરક્ષિત'
  },
  mr: {
    detectionOff: 'डिटेक्शन बंद आहे',
    scanning: '🔍 दुर्भावनायुक्त URL स्कॅन केले जात आहे...',
    scanTimeout: '⚠️ स्कॅनला खूप वेळ लागत आहे - परिणाम आंशिक असू शकतात',
    rateLimited: '⚠️ API दर मर्यादा गाठली - काही URL तपासले जाऊ शकत नाहीत',
    noUrlsFound: '✅ या पृष्ठावर कोणतीही URL आढळली नाही',
    pageSafe: (count) => `✅ पृष्ठ सुरक्षित वाटते (${count} URL स्कॅन केले)`,
    threatsDetected: (count) => `⚠️ ${count} दुर्भावनायुक्त URL${count > 1 ? ' आढळले' : ' आढळले'}!`,
    urlsScanned: 'URL स्कॅन केले',
    threatsFound: 'धोके आढळले',
    verifiedSafe: 'सत्यापित सुरक्षित',
    detectedThreats: '⚠️ आढळलेले धोके',
    recentScans: '📊 अलीकडील स्कॅन',
    refreshScan: '🔄 स्कॅन रिफ्रेश करा',
    viewDetails: '📋 तपशील पहा',
    malicious: 'दुर्भावनायुक्त',
    safe: 'सुरक्षित'
  }
};

// Detect language from storage or browser
function detectLanguage(callback) {
  // Check if language is stored in sync storage (set by user)
  chrome.storage.sync.get(['phishscan_language'], (result) => {
    const storedLang = result.phishscan_language;
    if (storedLang && (storedLang === 'hi' || storedLang === 'gu' || storedLang === 'mr' || storedLang === 'en')) {
      if (callback) callback(storedLang);
      return storedLang;
    }

    // Fallback to browser language
    const browserLang = navigator.language || navigator.userLanguage || 'en';
    const langCode = browserLang.split('-')[0].toLowerCase();

    let finalLang = 'en';
    if (langCode === 'hi' || langCode === 'gu' || langCode === 'mr') {
      finalLang = langCode;
    }

    if (callback) callback(finalLang);
    return finalLang;
  });
}

// Get current language synchronously (for immediate use)
function getCurrentLanguage() {
  // Try to get from sync storage synchronously (may not work, but try)
  try {
    const stored = chrome.storage.sync.get(['phishscan_language'], () => { });
  } catch (e) { }

  // Fallback to browser language
  const browserLang = navigator.language || navigator.userLanguage || 'en';
  const langCode = browserLang.split('-')[0].toLowerCase();

  if (langCode === 'hi' || langCode === 'gu' || langCode === 'mr') {
    return langCode;
  }
  return 'en';
}

// Set language preference
function setLanguage(lang) {
  chrome.storage.sync.set({ phishscan_language: lang }, () => {
    // Also notify content script to update
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'LANGUAGE_CHANGED', language: lang });
      }
    });
    // Refresh popup UI
    updatePopupLabels();
    updateStatusAndList();
  });
}

// Get translated text
function t(key, ...args) {
  const lang = getCurrentLanguage();
  const langTranslations = translations[lang] || translations.en;
  const translation = langTranslations[key];

  if (typeof translation === 'function') {
    return translation(...args);
  }
  return translation || translations.en[key];
}

let enabled = true;
let scanComplete = false;
let scanTimeout = null;
let statusCheckInterval = null;

// DOM elements
const toggle = document.getElementById('toggle');
const toggleLabel = document.getElementById('toggle-label');
const safeModeToggle = document.getElementById('safemode-toggle'); // New
const safeModeLabel = document.getElementById('safemode-label'); // New
const statusDiv = document.getElementById('status');
const list = document.getElementById('malicious-list');
const refreshBtn = document.getElementById('refresh-btn');
const totalScannedEl = document.getElementById('total-scanned');
const maliciousCountEl = document.getElementById('malicious-count');
const cleanCountEl = document.getElementById('clean-count');
const threatsSection = document.getElementById('threats-section');
const summarySection = document.getElementById('summary-section');
const summaryTable = document.getElementById('summary-table');
const detailsModal = document.getElementById('details-modal');
const modalBody = document.getElementById('modal-body');
const closeModal = document.querySelector('.close-modal');
const viewDetailsBtn = document.getElementById('view-details-btn');
const languageSelect = document.getElementById('language-select');

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  loadToggleState();
  loadLanguagePreference(); // Load saved language preference
  updatePopupLabels(); // Update labels based on detected language
  updateStatusAndList();

  // Set up event listeners
  toggle.addEventListener('change', handleToggleChange);
  safeModeToggle.addEventListener('change', handleSafeModeChange); // New
  refreshBtn.addEventListener('click', handleRefresh);
  languageSelect.addEventListener('change', (e) => {
    setLanguage(e.target.value);
  });
  closeModal.addEventListener('click', () => {
    detailsModal.classList.remove('show');
  });
  viewDetailsBtn.addEventListener('click', () => {
    showDetailsModal();
  });

  // Close modal when clicking outside
  detailsModal.addEventListener('click', (e) => {
    if (e.target === detailsModal) {
      detailsModal.classList.remove('show');
    }
  });
});

// Load language preference
function loadLanguagePreference() {
  chrome.storage.sync.get(['phishscan_language'], (result) => {
    const savedLang = result.phishscan_language || getCurrentLanguage();
    if (languageSelect) {
      languageSelect.value = savedLang;
    }
  });
}

// Update popup UI labels based on detected language
function updatePopupLabels() {
  const lang = detectLanguage();
  const langTranslations = translations[lang] || translations.en;

  // Update stat labels
  const statLabels = document.querySelectorAll('.stat-label');
  if (statLabels.length >= 3) {
    statLabels[0].textContent = langTranslations.urlsScanned;
    statLabels[1].textContent = langTranslations.threatsFound;
    statLabels[2].textContent = langTranslations.verifiedSafe;
  }

  // Update section headers
  const threatsHeader = document.querySelector('#threats-section h3');
  if (threatsHeader) threatsHeader.textContent = langTranslations.detectedThreats;

  const summaryHeader = document.querySelector('#summary-section h3');
  if (summaryHeader) summaryHeader.textContent = langTranslations.recentScans;

  // Update button labels
  if (refreshBtn) refreshBtn.textContent = langTranslations.refreshScan;
  if (viewDetailsBtn) viewDetailsBtn.textContent = langTranslations.viewDetails;

  // Update toggle label
  updateToggleLabel();
}

// Load toggle state from storage
function loadToggleState() {
  chrome.storage.sync.get(['phishscan_enabled', 'phishscan_safemode'], (result) => {
    // Default Detection to ON if not set
    enabled = result.phishscan_enabled !== false;
    if (result.phishscan_enabled === undefined) {
      chrome.storage.sync.set({ phishscan_enabled: true });
      enabled = true;
    }
    toggle.checked = enabled;
    updateToggleLabel();

    // Default Safe Mode to FALSE if not set (or true if user requested standard "parents" recommendation? Plan said default false, let's stick to false)
    const safeModeEnabled = result.phishscan_safemode === true;
    safeModeToggle.checked = safeModeEnabled;
    updateSafeModeLabel();
  });
}

function updateSafeModeLabel() {
  const isSafe = safeModeToggle.checked;
  safeModeLabel.style.color = isSafe ? '#059669' : '#4b5563';
  safeModeLabel.textContent = isSafe ? 'Safe Mode ON' : 'Safe Mode (Parents)';
}

function handleSafeModeChange() {
  const isSafe = safeModeToggle.checked;
  chrome.storage.sync.set({ phishscan_safemode: isSafe });
  // Also set in local purely for content script fast access if needed, but sync is fine usually. 
  // Content script handles storage.sync too.
  updateSafeModeLabel();
}

// Update toggle label
function updateToggleLabel() {
  const lang = detectLanguage();
  const langTranslations = translations[lang] || translations.en;
  toggleLabel.textContent = enabled
    ? (lang === 'hi' ? 'डिटेक्शन चालू' : lang === 'gu' ? 'ડિટેક્શન ચાલુ' : 'Detection ON')
    : t('detectionOff');
}

// Handle toggle change
function handleToggleChange() {
  enabled = toggle.checked;
  chrome.storage.sync.set({ phishscan_enabled: enabled });
  updateToggleLabel();

  if (enabled) {
    forceRescanOnCurrentTab();
  } else {
    chrome.storage.local.remove(['phishscan_found', 'phishscan_scanning', 'phishscan_clean', 'phishscan_total_scanned']);
    updateStatusAndList();
  }
}

// Force rescan on current tab
function forceRescanOnCurrentTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].id) {
      const url = tabs[0].url;

      // Strict check for allowed schemes only
      if (!url || (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('file://'))) {
        console.log('Skipping scan on restricted or system page:', url);
        const statusDiv = document.getElementById('status');
        if (statusDiv) {
          statusDiv.textContent = 'System Page (Not Scanned)';
          statusDiv.className = 'status safe';
        }
        return;
      }

      try {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          function: () => {
            chrome.storage.local.remove(['phishscan_found', 'phishscan_scanning', 'phishscan_clean', 'phishscan_total_scanned']);
            chrome.runtime.sendMessage({ type: 'FORCE_SCAN' });
          }
        }).catch(err => console.log('Script execution blocked or failed:', err));
      } catch (e) {
        console.log('Synchronous script execution error:', e);
      }
    }
  });
}

// Handle refresh button
function handleRefresh() {
  if (enabled) {
    forceRescanOnCurrentTab();
    updateStatusAndList();
  }
}


// Show detailed analysis modal
function showDetailedAnalysisModal(data, url) {
  detailsModal.classList.add('show');

  let html = `
    <div class="detail-section">
      <h4>📋 URL Information</h4>
      <div class="detail-item">
        <span class="detail-label">URL:</span>
        <span class="detail-value">${escapeHtml(url)}</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Status:</span>
        <span class="detail-value">
          <span class="summary-status ${data.malicious ? 'malicious' : 'safe'}">
            ${data.malicious ? '⚠️ Malicious' : '✅ Safe'}
          </span>
        </span>
      </div>
    </div>
  `;

  if (data.responseCode === 1) {
    html += `
      <div class="detail-section">
        <h4>📊 Detection Results</h4>
        <div class="detail-item">
          <span class="detail-label">Detection Rate:</span>
          <span class="detail-value"><strong>${data.positives}/${data.total}</strong> engines detected</span>
        </div>
        ${data.detectionRate ? `
          <div class="detail-item">
            <span class="detail-label">Detection Percentage:</span>
            <span class="detail-value">${data.detectionRate}%</span>
          </div>
        ` : ''}
        ${data.scanDate ? `
          <div class="detail-item">
            <span class="detail-label">Last Scan:</span>
            <span class="detail-value">${new Date(data.scanDate * 1000).toLocaleString()}</span>
          </div>
        ` : ''}
        ${data.firstSubmission ? `
          <div class="detail-item">
            <span class="detail-label">First Submission:</span>
            <span class="detail-value">${new Date(data.firstSubmission * 1000).toLocaleString()}</span>
          </div>
        ` : ''}
        ${data.lastSubmission ? `
          <div class="detail-item">
            <span class="detail-label">Last Submission:</span>
            <span class="detail-value">${new Date(data.lastSubmission * 1000).toLocaleString()}</span>
          </div>
        ` : ''}
      </div>
    `;

    if (data.threatLabels && data.threatLabels.length > 0) {
      html += `
        <div class="detail-section">
          <h4>🏷️ Threat Labels</h4>
          <div class="detail-item">
            <span class="detail-label">Labels:</span>
            <span class="detail-value">${data.threatLabels.join(', ')}</span>
          </div>
        </div>
      `;
    }

    if (data.categories && data.categories.length > 0) {
      html += `
        <div class="detail-section">
          <h4>📁 Categories</h4>
          <div class="detail-item">
            <span class="detail-label">Categories:</span>
            <span class="detail-value">${data.categories.join(', ')}</span>
          </div>
        </div>
      `;
    }

    if (data.detectedBy && data.detectedBy.length > 0) {
      html += `
        <div class="detail-section">
          <h4>🔍 Detection Engines</h4>
          <div class="detection-engines">
      `;

      data.detectedBy.forEach(engine => {
        html += `
          <div class="engine-item detected">
            <strong>${escapeHtml(engine.engine)}</strong><br>
            ${escapeHtml(engine.result)}
          </div>
        `;
      });

      html += `
          </div>
        </div>
      `;
    }

    if (data.permalink) {
      html += `
        <div class="detail-section">
          <h4>🔗 Full Report</h4>
          <div class="detail-item">
            <span class="detail-label">VirusTotal Link:</span>
            <span class="detail-value">
              <a href="${data.permalink}" target="_blank" style="color: #667eea; text-decoration: none;">
                View on VirusTotal →
              </a>
            </span>
          </div>
        </div>
      `;
    }
  } else {
    html += `
      <div class="detail-section">
        <h4>ℹ️ Status</h4>
        <div class="detail-item">
          <span class="detail-label">Message:</span>
          <span class="detail-value">${escapeHtml(data.verboseMsg || data.reason || 'Unknown status')}</span>
        </div>
      </div>
    `;
  }

  modalBody.innerHTML = html;
}

// Show details modal from threats list
function showDetailsModal() {
  chrome.storage.local.get(['phishscan_found'], (result) => {
    const threats = result.phishscan_found || [];
    if (threats.length > 0 && threats[0].virustotalData) {
      showDetailedAnalysisModal(threats[0].virustotalData, threats[0].url);
    }
  });
}

// Enhanced status and list update
function updateStatusAndList() {
  if (!enabled) {
    statusDiv.textContent = t('detectionOff');
    statusDiv.className = 'status';
    list.innerHTML = '';
    totalScannedEl.textContent = '0';
    maliciousCountEl.textContent = '0';
    cleanCountEl.textContent = '0';
    threatsSection.style.display = 'none';
    summarySection.style.display = 'none';
    viewDetailsBtn.style.display = 'none';
    return;
  }

  // Always trigger a fresh scan for the current tab when the popup opens/refreshes
  forceRescanOnCurrentTab();

  statusDiv.textContent = t('scanning');
  statusDiv.className = 'status scanning';
  list.innerHTML = '';
  summaryTable.innerHTML = '';

  // Set a timeout for scan completion (UI safety net; actual scan is capped in content.js)
  if (scanTimeout) {
    clearTimeout(scanTimeout);
  }
  scanTimeout = setTimeout(() => {
    statusDiv.textContent = t('scanTimeout');
    statusDiv.className = 'status error';
  }, 8000); // 8 second UI timeout

  // Check scan status
  function checkScanStatus() {
    chrome.storage.local.get([
      'phishscan_scanning',
      'phishscan_found',
      'phishscan_clean',
      'phishscan_total_scanned',
      'phishscan_rate_limited'
    ], (result) => {
      if (scanTimeout) {
        clearTimeout(scanTimeout);
        scanTimeout = null;
      }

      const scanning = result.phishscan_scanning === true;
      const found = result.phishscan_found || [];
      const clean = result.phishscan_clean || [];
      const totalScanned = result.phishscan_total_scanned || 0;
      const rateLimited = result.phishscan_rate_limited === true;

      if (scanning || !result.hasOwnProperty('phishscan_found')) {
        setTimeout(checkScanStatus, 500);
        return;
      }

      scanComplete = true;
      list.innerHTML = '';
      summaryTable.innerHTML = '';

      // Update stats
      totalScannedEl.textContent = totalScanned;
      maliciousCountEl.textContent = found.length;
      cleanCountEl.textContent = clean.length;

      if (rateLimited) {
        statusDiv.textContent = t('rateLimited');
        statusDiv.className = 'status error';
      } else if (found.length === 0 && clean.length === 0 && totalScanned === 0) {
        statusDiv.textContent = t('noUrlsFound');
        statusDiv.className = 'status safe';
      } else if (found.length === 0) {
        statusDiv.textContent = t('pageSafe', totalScanned);
        statusDiv.className = 'status safe';
      } else {
        statusDiv.textContent = t('threatsDetected', found.length);
        statusDiv.className = 'status threat';
        threatsSection.style.display = 'block';
        viewDetailsBtn.style.display = 'block';
      }

      // Display threats
      found.forEach((threat, index) => {
        const li = document.createElement('li');
        li.onclick = () => {
          if (threat.virustotalData) {
            showDetailedAnalysisModal(threat.virustotalData, threat.url);
          }
        };

        let threatDisplay = `
          <span class="threat-number">${index + 1}.</span>
          <span class="threat-url">${escapeHtml(threat.url)}</span>
          <div class="threat-reason">${escapeHtml(threat.reason)}</div>
        `;

        if (threat.isShortened && threat.resolvedUrl && threat.resolvedUrl !== threat.url) {
          threatDisplay += `
            <div class="threat-shortened">
              🔗 Resolved to: ${escapeHtml(threat.resolvedUrl)}
            </div>
          `;
        }

        if (threat.virustotalData) {
          const vt = threat.virustotalData;
          threatDisplay += `
            <div class="threat-virustotal">
              🛡️ VirusTotal: ${vt.positives}/${vt.total} engines detected
              ${vt.detectionRate ? ` (${vt.detectionRate}%)` : ''}
            </div>
          `;
        }

        li.innerHTML = threatDisplay;
        list.appendChild(li);
      });

      // Display summary table
      if (found.length > 0 || clean.length > 0) {
        summarySection.style.display = 'block';

        // Add malicious URLs to summary
        found.forEach(threat => {
          const row = document.createElement('div');
          row.className = 'summary-row';
          row.innerHTML = `
            <span class="summary-url">${escapeHtml(threat.url.substring(0, 50))}${threat.url.length > 50 ? '...' : ''}</span>
            <span class="summary-status malicious">${t('malicious')}</span>
          `;
          summaryTable.appendChild(row);
        });

        // Add clean URLs to summary (limited to first 10)
        clean.slice(0, 10).forEach(item => {
          const row = document.createElement('div');
          row.className = 'summary-row';
          row.innerHTML = `
            <span class="summary-url">${escapeHtml(item.url.substring(0, 50))}${item.url.length > 50 ? '...' : ''}</span>
            <span class="summary-status safe">${t('safe')}</span>
          `;
          summaryTable.appendChild(row);
        });
      }
    });
  }

  checkScanStatus();
}

// Utility function to escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Cleanup on popup close
window.addEventListener('beforeunload', () => {
  if (scanTimeout) {
    clearTimeout(scanTimeout);
  }
  if (statusCheckInterval) {
    clearInterval(statusCheckInterval);
  }
});

