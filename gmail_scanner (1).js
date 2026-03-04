/**
 * Gmail PhishScan Integration
 * Detects opened emails, scans content, and displays security analysis.
 */

// Debug Logger
const DEBUG = true;
function log(msg, data = '') {
  if (DEBUG) console.log(`[PhishScan Gmail] ${msg}`, data);
}

// Configuration & Selectors (Gmail DOM is obfuscated, these are best-effort standard selectors)
const SELECTORS = {
  // .a3s is the standard class for the message body content in Gmail
  emailContainer: '.a3s',
  // h2.hP is the standard class for the conversation title (Subject)
  subject: 'h2.hP',
  // .gD is the standard class for the sender's name/email wrapper
  senderWrapper: '.gD',
  senderEmail: '.gD', // Often the email is in the 'email' attribute of this span, or inside it
  // Attachments are tricky; usually check for specific download/drive icons or classes like .aZo
  attachments: '.aZo',
};

// Risk Scoring Constants (Copied/Adapted from content.js for consistency)
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'confirm', 'pay',
  'bonus', 'free', 'gift', 'prize', 'urgent', 'suspend', 'action required', 'immediate',
  'unauthorized', 'lock', 'invoice', 'statement', 'tax', 'irs', 'ups', 'fedex', 'delivery'
];
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.info', '.site', '.live', '.gq', '.tk', '.ml', '.ga', '.cf', '.buzz', '.cn', '.vip', '.work'];

// State
let currentlyScanning = false;
let lastScannedEmailId = null; // This variable is no longer used with the new scanning logic
let scanTooltip = null; // This variable is no longer used with the new scanning logic

// =============================================================================
// CORE LOGIC
// =============================================================================

function init() {
  log('Initializing Gmail Scanner v2.0...');

  // 1. Run immediately in case an email is already open (e.g. reload on open email)
  checkAndScan();

  // 2. Use a mutation observer to detect when new emails are opened
  const observer = new MutationObserver(debounce(checkAndScan, 1000));
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

function checkAndScan() {
  // Look for all email bodies currently in the DOM
  const emailBodies = document.querySelectorAll(SELECTORS.emailContainer);

  if (emailBodies.length > 0) {
    log(`Found ${emailBodies.length} email containers.`);

    // In a conversation view, there may be multiple .a3s containers (collapsed emails).
    // We usually want to scan the *last* one (the one being viewed/replied to)
    // OR scan all of them if they are expanded.
    // For this implementation, let's scan ANY that are visible and haven't been scanned.

    emailBodies.forEach(emailNode => {
      // Check if visible (offsetParent is null if hidden)
      if (emailNode.offsetParent !== null && !emailNode.hasAttribute('data-phishscan-scanned')) {
        startScan(emailNode);
      }
    });
  }
}

async function startScan(emailNode) {
  // Mark as scanned immediately to prevent double-scan
  emailNode.setAttribute('data-phishscan-scanned', 'true');

  log('Starting scan on email node', emailNode);

  // 1. Inject "Scanning" UI
  const uiContainer = ensureUiContainer(emailNode);
  if (!uiContainer) return; // Should not happen

  updateUiState(uiContainer, 'scanning');

  try {
    // 2. Extract Data
    const data = extractEmailData(emailNode);
    log('Extracted Data:', data);

    // 3. Perform Analysis (Simulated Backend Delay for "Intelligence" feel + Actual Analysis)
    // Increased delay to allow users to see "Scanning Attachments..." texts
    await new Promise(r => setTimeout(r, 2500));

    const analysis = analyzeEmail(data);
    log('Analysis Result:', analysis);

    // 4. Update UI with Results
    updateUiState(uiContainer, 'result', analysis);

    // 5. Apply Hover Protections if High Risk
    if (analysis.riskLevel === 'HIGH') {
      applyHoverProtections(emailNode, analysis);
    }

  } catch (e) {
    console.error('Scan failed:', e);
    updateUiState(uiContainer, 'error');
  } finally {
    // currentlyScanning = false; // Removed as it's not needed with the new per-email scanning logic
  }
}

// =============================================================================
// DATA EXTRACTION & ANALYSIS
// =============================================================================

function extractEmailData(emailNode) {
  // Traversing up to find the container of the message (div.gs) to find the sender info relative to THIS email
  // This is hard because .a3s is deep inside.
  // Fallback: Look for the closest globally visible header info if we can't find specific ones.

  // Subject: Usually implies thread title.
  const subjectEl = document.querySelector(SELECTORS.subject);
  const subject = subjectEl ? subjectEl.textContent.trim() : 'Active Conversation';

  // Sender: THIS is the hardest part in Gmail.
  // We need to find the specific sender for *this* email body.
  // The structure is roughly: .gs -> .gE -> .gD (sender) ... .a3s (body)
  // Let's look for a .gD (sender name) that is physically above the email body in the DOM tree.

  let senderName = 'Unknown Sender';
  let senderEmail = 'unknown@email.com';

  // Try to find the closest wrapper parent
  const parentMessageContainer = emailNode.closest('.gs');
  if (parentMessageContainer) {
    const senderEl = parentMessageContainer.querySelector(SELECTORS.senderWrapper);
    if (senderEl) {
      senderName = senderEl.innerText;
      senderEmail = senderEl.getAttribute('email') || senderEl.innerText; // .gD often has 'email' attr
    }
  } else {
    // Fallback: Just grab the last visible sender on screen
    const senders = document.querySelectorAll(SELECTORS.senderWrapper);
    if (senders.length > 0) {
      const lastSender = senders[senders.length - 1];
      senderName = lastSender.innerText;
      senderEmail = lastSender.getAttribute('email') || lastSender.innerText;
    }
  }

  // Clean email
  if (senderEmail.includes('<')) {
    senderEmail = senderEmail.match(/<([^>]+)>/)?.[1] || senderEmail;
  }

  // Body Text
  const bodyText = emailNode.innerText;

  // Links
  const links = Array.from(emailNode.querySelectorAll('a')).map(a => ({
    text: a.innerText,
    href: a.href,
    element: a
  }));

  // Attachments
  // Look for .aZo which is often used for attachment filenames
  const attachmentLinks = document.querySelectorAll(SELECTORS.attachments);
  const attachments = Array.from(attachmentLinks)
    .filter(el => el.offsetParent !== null) // Visible ones
    .map(a => a.textContent || 'Unnamed File');

  return { subject, senderName, senderEmail, bodyText, links, attachments };
}

function analyzeEmail(data) {
  let score = 0;
  let reasons = [];

  // 1. Sender Analysis
  const safeDomains = ['gmail.com', 'google.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'];
  let senderDomain = data.senderEmail.split('@')[1];

  if (senderDomain) {
    if (SUSPICIOUS_TLDS.some(tld => senderDomain.endsWith(tld))) {
      score += 40;
      reasons.push(`Suspicious sender domain TLD (${senderDomain})`);
    }

    // Check for mismatch (e.g. "PayPal Support" from "bob@random-site.com")
    const brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'bank'];
    brands.forEach(brand => {
      if (data.senderName.toLowerCase().includes(brand) && !senderDomain.includes(brand)) {
        score += 50;
        reasons.push(`Potential Spoofing: Sender claims to be ${brand} but email is from ${senderDomain}`);
      }
    });
  }

  // 2. Keyword/Urgency Analysis
  let urgencyCount = 0;
  let foundKeywords = new Set();

  SUSPICIOUS_KEYWORDS.forEach(kw => {
    if (data.bodyText.toLowerCase().includes(kw)) {
      urgencyCount++;
      foundKeywords.add(kw);
    }
    if (data.subject.toLowerCase().includes(kw)) {
      urgencyCount++; // Double weight for subject
      foundKeywords.add(kw);
    }
  });

  if (urgencyCount > 2) {
    score += 50; // Boost score significantly if multiple urgency keywords are found
    const keywordsList = Array.from(foundKeywords).slice(0, 3).join(', ');
    reasons.push(`High Urgency/Suspicious Language detected: "${keywordsList}"`);
  } else if (urgencyCount > 0) {
    score += 15;
    const keywordsList = Array.from(foundKeywords).slice(0, 3).join(', ');
    reasons.push(`Suspicious language detected: "${keywordsList}"`);
  }

  // 3. Link Analysis
  let suspiciousLinks = 0;
  data.links.forEach(link => {
    // Reuse the heuristic logic logic simply
    if (checkForSuspiciousLink(link.href)) {
      suspiciousLinks++;
    }
  });

  if (suspiciousLinks > 0) {
    score += 25 * suspiciousLinks;
    reasons.push(`Contains ${suspiciousLinks} suspicious link(s)`);
  }

  // 4. Attachment Analysis
  const riskyExts = ['.scr', '.exe', '.bat', '.cmd', '.js', '.vbs', '.iso'];
  data.attachments.forEach(att => {
    if (riskyExts.some(ext => att.toLowerCase().endsWith(ext))) {
      score += 60;
      reasons.push(`High-risk attachment detected: ${att}`);
    }
  });

  // Cap score
  score = Math.min(score, 100);

  // Determine Level (Lower threshold to catch more phishing)
  let level = 'SAFE';
  if (score >= 50) level = 'HIGH';
  else if (score >= 20) level = 'MEDIUM';

  // If no reasons but low score, give a positive reason
  if (reasons.length === 0) reasons.push('No immediate threats detected');

  return { riskScore: score, riskLevel: level, reasons, sender: data.senderEmail };
}

function checkForSuspiciousLink(url) {
  try {
    const urlObj = new URL(url);
    if (urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1') return false;

    // IP based?
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname)) return true;

    // Suspicious TLD?
    if (SUSPICIOUS_TLDS.some(tld => urlObj.hostname.endsWith(tld))) return true;

    // Long subdomain?
    if (urlObj.hostname.length > 50) return true;

    return false;
  } catch (e) { return false; }
}


// =============================================================================
// UI RENDERING
// =============================================================================

function ensureUiContainer(emailNode) {
  // We want to insert the dashboard at the TOP of the email body, or just before it.
  // emailNode is .a3s (the body). Let's insert as the first child.

  let container = emailNode.querySelector('.phishscan-gmail-dashboard');
  if (!container) {
    container = document.createElement('div');
    container.className = 'phishscan-gmail-dashboard';
    // Insert at the very top of the email body
    emailNode.insertBefore(container, emailNode.firstChild);
  }
  return container;
}

function updateUiState(container, state, data = null) {
  container.innerHTML = ''; // Clear current

  const style = `
    display: flex;
    align-items: center;
    padding: 12px 16px;
    margin-bottom: 20px;
    border-radius: 8px;
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
    transition: all 0.3s ease;
    border: 1px solid #e0e0e0;
    color: #202124;
    background: #f8f9fa; /* Subtle background to distinguish from email body */
    font-size: 14px;
    position: relative;
    overflow: hidden;
  `;

  container.setAttribute('style', style);

  if (state === 'scanning') {
    renderScanningState(container);
  } else if (state === 'result') {
    renderResultState(container, data);
  } else if (state === 'error') {
    container.innerHTML = `<span style="color:#d93025; font-weight:500">⚠ Security Scan Error. Please try again.</span>`;
  }
}

function renderScanningState(container) {
  // Minimalist scanning animation
  container.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px; width: 100%;">
      <div class="phishscan-spinner"></div>
      <div class="phishscan-text-rotator">
        <span>${t('analyzingSender')}</span>
      </div>
    </div>
    <style>
      .phishscan-spinner {
        width: 18px;
        height: 18px;
        border: 2px solid #f3f3f3;
        border-top: 2px solid #1a73e8;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      }
      @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
      .phishscan-text-rotator {
        font-weight: 500;
        color: #5f6368;
        animation: fadeText 1.5s infinite alternate;
      }
      @keyframes fadeText { 0% { opacity: 0.7; } 100% { opacity: 1; } }
    </style>
  `;

  // Simple text rotation effect
  const texts = [
    t('analyzingSender'),
    t('checkingReputation'),
    t('scanningLinks'),
    t('scanningAttachments'),
    t('verifyingSignatures')
  ];
  let idx = 0;
  const txtEl = container.querySelector('.phishscan-text-rotator span');
  const interval = setInterval(() => {
    idx = (idx + 1) % texts.length;
    if (txtEl) txtEl.textContent = texts[idx];
  }, 800);

  // Store interval on container to clear it later if needed (though innerHTML clear handles visual removal)
  container._scanInterval = interval;
}

// Keep preferences in sync
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync') {
    if (changes.phishscan_language) currentLang = changes.phishscan_language.newValue;
    if (changes.phishscan_safemode) safeModeEnabled = changes.phishscan_safemode.newValue === true;
  }
});

function renderResultState(container, data) {
  if (container._scanInterval) clearInterval(container._scanInterval);

  // Determine Theme
  let theme = {
    color: '#188038', // Green
    bg: '#e6f4ea',
    icon: '🛡️',
    title: t('lowRisk')
  };

  if (data.riskLevel === 'HIGH') {
    theme = { color: '#d93025', bg: '#fce8e6', icon: '🚨', title: t('highRisk') };
  } else if (data.riskLevel === 'MEDIUM') {
    theme = { color: '#e37400', bg: '#fef7e0', icon: '⚠️', title: t('mediumRisk') };
  }

  // Override container style for result
  container.style.borderLeft = `6px solid ${theme.color}`;

  // Result HTML
  const reasonsHtml = data.reasons.map(r => `<li style="margin-bottom: 4px;">${r}</li>`).join('');

  // If no reasons, use safe message
  const displayReasons = reasonsHtml || `<li>${t('noThreats')}</li>`;

  // Contextual Learning (Safe Mode OFF only + Risk Detected)
  let learningTipHtml = '';
  // Only show if NOT safe mode AND risk is NOT SAFE
  if (!safeModeEnabled && data.riskLevel !== 'SAFE') {
    let tipKey = 'tip_general';

    // Simple heuristic for tip selection
    const reasonsStr = data.reasons.join(' ').toLowerCase();
    if (reasonsStr.includes('urgency') || reasonsStr.includes('urgent')) {
      tipKey = 'tip_urgency';
    } else if (reasonsStr.includes('brand') || reasonsStr.includes('spoofing')) {
      tipKey = 'tip_brand';
    } else if (reasonsStr.includes('suspicious link') || reasonsStr.includes('tld')) {
      tipKey = 'tip_suspicious_link';
    }

    const tipContent = t(tipKey).replace('💡 ', '').replace('Insight:', '').trim(); // Clean content

    learningTipHtml = `
      <div class="phishscan-learning-container" style="margin-top: 12px;">
        <div class="phishscan-learn-trigger" role="button" tabindex="0" title="${t('learn_more')}" style="
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 12px;
          background: #f1f3f4;
          border-radius: 16px;
          font-size: 12px;
          font-weight: 500;
          color: #444746;
          cursor: pointer;
          transition: background 0.2s;
          border: 1px solid transparent;
        ">
          <span>💡</span>
          <span>${t('learn_why')}</span>
        </div>
        <div class="phishscan-learn-content" style="
          display: none;
          margin-top: 8px;
          padding: 12px;
          background: #f8f9fa;
          border-radius: 8px;
          font-size: 13px;
          color: #0d652d;
          border: 1px solid #e1e3e1;
          line-height: 1.4;
          box-shadow: 0 1px 2px rgba(0,0,0,0.05);
          animation: phishscan-fade-in 0.2s ease-out;
        ">
          ${tipContent}
        </div>
      </div>
    `;
  }

  container.innerHTML = `
    <div style="display: flex; align-items: flex-start; gap: 16px; width: 100%;">
      <div style="font-size: 24px; line-height: 1;">${theme.icon}</div>
      <div style="flex: 1;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: ${theme.color};">${theme.title}</h3>
        </div>
        <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #3c4043; line-height: 1.5;">
          ${displayReasons}
        </ul>
        ${learningTipHtml}
      </div>
    </div>
  `;

  // Add click handler for learning trigger
  if (!safeModeEnabled && data.riskLevel !== 'SAFE') {
    const trigger = container.querySelector('.phishscan-learn-trigger');
    const content = container.querySelector('.phishscan-learn-content');

    if (trigger && content) {
      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isHidden = content.style.display === 'none';
        content.style.display = isHidden ? 'block' : 'none';
        trigger.style.background = isHidden ? '#e8eaed' : '#f1f3f4';
        trigger.setAttribute('aria-expanded', isHidden);
      });

      // Hover effect via JS to keep styles inclusive
      trigger.addEventListener('mouseenter', () => { trigger.style.background = '#e2e7eb'; });
      trigger.addEventListener('mouseleave', () => {
        trigger.style.background = content.style.display === 'none' ? '#f1f3f4' : '#e8eaed';
      });
    }
  }
}

// =============================================================================
// MODAL & INTERACTION
// =============================================================================

function createModalStyles() {
  return `
    .phishscan-modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(4px);
      z-index: 2147483647; /* Max z-index */
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: 'Google Sans', Roboto, sans-serif;
    }
    .phishscan-modal-content {
      background: white;
      border-radius: 12px;
      padding: 32px;
      width: 90%;
      max-width: 480px;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
      text-align: center;
      animation: phishscan-slide-in 0.3s ease-out;
    }
    @keyframes phishscan-slide-in {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .phishscan-warning-icon {
      font-size: 48px;
      margin-bottom: 20px;
      display: block;
    }
    .phishscan-title {
      color: #d93025;
      font-size: 22px;
      font-weight: 700;
      margin: 0 0 12px 0;
    }
    .phishscan-message {
      color: #3c4043;
      font-size: 15px;
      line-height: 1.6;
      margin-bottom: 24px;
    }
    .phishscan-url {
      background: #f1f3f4;
      padding: 10px 14px;
      border-radius: 8px;
      font-family: monospace;
      color: #d93025;
      font-size: 13px;
      margin-bottom: 28px;
      word-break: break-all;
      border: 1px solid #dadce0;
    }
    .phishscan-actions {
      display: flex;
      gap: 12px;
      justify-content: center;
    }
    .phishscan-btn {
      padding: 10px 24px;
      border-radius: 20px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      border: none;
      transition: transform 0.1s;
    }
    .phishscan-btn:active { transform: scale(0.98); }
    .phishscan-btn-safe {
      background: #1a73e8;
      color: white;
      box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    .phishscan-btn-safe:hover { background: #1557b0; }
    .phishscan-btn-danger {
      background: transparent;
      color: #5f6368;
      border: 1px solid #dadce0;
    }
    .phishscan-btn-danger:hover {
      background: #f1f3f4;
      color: #202124;
    }
  `;
}

// Translation System
const TRANSLATIONS = {
  en: {
    suspicious: '⚠ Suspicious',
    highRisk: 'High Risk Detected',
    mediumRisk: 'Medium Risk – Suspicious Email',
    lowRisk: 'Low Risk – No Issues Detected',
    suspiciousLink: 'Suspicious Link',
    riskScore: 'Risk Score',
    flaggedMsg: 'PhishScan has flagged this link. Proceed with caution.',
    securityWarning: 'Security Warning',
    flaggedHighRisk: 'This link has been flagged as high risk.',
    reason: 'Reason',
    goBack: 'Go Back (Recommended)',
    proceed: 'Proceed Anyway',
    safeModeOn: 'Safe Mode is ON. Unsafe navigation is blocked.',
    analyzingSender: 'Analyzing Sender...',
    checkingReputation: 'Checking Domain Reputation...',
    scanningLinks: 'Scanning Links...',
    scanningAttachments: 'Scanning Attachments for Malware...',
    verifyingSignatures: 'Verifying Security Signatures...',
    safeEmail: 'Safe Email',
    suspiciousActivity: 'Suspicious Activity',
    noThreats: 'No immediate threats detected',
    scanError: '⚠ Security Scan Error. Please try again.',
    tip_urgency: '💡 Insight: Fake messages use urgency to make you panic and click without thinking.',
    tip_brand: '💡 Insight: Real companies will never ask you to login via email links.',
    tip_suspicious_link: '💡 Insight: Phishing sites often copy logos but use slightly different web addresses.',
    tip_general: '💡 Insight: Always hover over links to see the real destination before clicking.',
    learn_why: 'Learn why',
    learn_more: 'Click to understand this threat'
  },
  hi: {
    suspicious: '⚠ संदिग्ध',
    highRisk: 'उच्च जोखिम',
    mediumRisk: 'मध्यम जोखिम – संदिग्ध ईमेल',
    lowRisk: 'कम जोखिम – सुरक्षित',
    suspiciousLink: 'संदिग्ध लिंक',
    riskScore: 'जोखिम स्कोर',
    flaggedMsg: 'PhishScan ने इस लिंक को संदिग्ध माना है। कृपया सावधान रहें।',
    securityWarning: 'सुरक्षा चेतावनी',
    flaggedHighRisk: 'इस लिंक को उच्च जोखिम के रूप में चिह्नित किया गया है।',
    reason: 'कारण',
    goBack: 'वापस जाएं (अनुशंसित)',
    proceed: 'फिर भी आगे बढ़ें',
    safeModeOn: 'सेफ मोड चालू है। असुरक्षित नेविगेशन अवरुद्ध है।',
    analyzingSender: 'प्रेषक का विश्लेषण कर रहा है...',
    checkingReputation: 'डोमेन प्रतिष्ठा की जांच हो रही है...',
    scanningLinks: 'लिंक स्कैन किए जा रहे हैं...',
    scanningAttachments: 'माैलवेयर के लिए अटैचमेंट स्कैन किए जा रहे हैं...',
    verifyingSignatures: 'सुरक्षा हस्ताक्षरों की पुष्टि की जा रही है...',
    safeEmail: 'सुरक्षित ईमेल',
    suspiciousActivity: 'संदिग्ध गतिविधि',
    noThreats: 'कोई तत्काल खतरा नहीं मिला',
    scanError: '⚠ सुरक्षा स्कैन त्रुटि। कृपया पुनः प्रयास करें।',
    tip_urgency: ' नकली संदेश आपको घबराने के लिए जल्दबाजी का उपयोग करते हैं।',
    tip_brand: ' असली कंपनियां कभी भी ईमेल लिंक के जरिए लॉग इन करने के लिए नहीं कहतीं।',
    tip_suspicious_link: ' फिशिंग साइटें अक्सर लोगो की नकल करती हैं लेकिन अलग वेब पते का उपयोग करती हैं।',
    tip_general: ' क्लिक करने से पहले हमेशा लिंक पर होवर करके असली पता देखें।',
    learn_why: 'जानें क्यों',
    learn_more: 'इस खतरे को समझने के लिए क्लिक करें'
  },
  gu: {
    suspicious: '⚠ શંકાસ્પદ',
    highRisk: 'ઉચ્ચ જોખમ',
    mediumRisk: 'મધ્યમ જોખમ – શંકાસ્પદ',
    lowRisk: 'ઓછું જોખમ – સુરક્ષિત',
    suspiciousLink: 'શંકાસ્પદ લિંક',
    riskScore: 'જોખમ સ્કોર',
    flaggedMsg: 'PhishScan એ આ લિંકને ફ્લેગ કરી છે. કૃપા કરીને સાવચેત રહો.',
    securityWarning: 'સુરક્ષા ચેતવણી',
    flaggedHighRisk: 'આ લિંકને ઉચ્ચ જોખમ તરીકે ચિહ્નિત કરવામાં આવી છે.',
    reason: 'કારણ',
    goBack: 'પાછા જાઓ (ભલામણ કરેલ)',
    proceed: 'તો પણ આગળ વધો',
    safeModeOn: 'સેફ મોડ ચાલુ છે. અસુરક્ષિત નેવિગેશન અવરોધિત છે.',
    analyzingSender: 'પ્રેષકનું વિશ્લેષણ કરી રહ્યું છે...',
    checkingReputation: 'ડોમેન પ્રતિષ્ઠા તપાસી રહ્યું છે...',
    scanningLinks: 'લિંક સ્કેન કરવામાં આવી રહી છે...',
    scanningAttachments: 'માલવેર માટે જોડાણો સ્કેન કરવામાં આવી રહ્યા છે...',
    verifyingSignatures: 'સુરક્ષા હસ્તાક્ષરોની ચકાસણી કરવામાં આવી રહી છે...',
    safeEmail: 'સુરક્ષિત ઇમેઇલ',
    suspiciousActivity: 'શંકાસ્પદ પ્રવૃત્તિ',
    noThreats: 'કોઈ તાત્કાલિક જોખમો મળ્યા નથી',
    scanError: '⚠ સુરક્ષા સ્કેન ભૂલ. કૃપા કરીને ફરી પ્રયાસ કરો.',
    tip_urgency: ' નકલી સંદેશાઓ તમને ગભરાવવા માટે ઉતાવળનો ઉપયોગ કરે છે.',
    tip_brand: ' સાચી કંપનીઓ ક્યારેય ઈમેલ લિંક્સ દ્વારા લોગિન કરવા માટે કહેતી નથી.',
    tip_suspicious_link: ' ફિશિંગ સાઇટ્સ ઘણીવાર લોગોની નકલ કરે છે પરંતુ અલગ વેબ સરનામાંનો ઉપયોગ કરે છે.',
    tip_general: ' ક્લિક કરતા પહેલા હંમેશા લિંક પર હોવર કરીને સાચું સરનામું જુઓ.',
    learn_why: 'શા માટે તે જાણો',
    learn_more: 'આ ખતરાને સમજવા માટે ક્લિક કરો'
  },
  mr: {
    suspicious: '⚠ संशयास्पद',
    highRisk: 'उच्च धोका',
    mediumRisk: 'मध्यम धोका – संशयास्पद',
    lowRisk: 'कमी धोका – सुरक्षित',
    suspiciousLink: 'संशयास्पद लिंक',
    riskScore: 'जोखीम स्कोअर',
    flaggedMsg: 'PhishScan ने ही लिंक फ्लॅग केली आहे. कृपया सावध रहा.',
    securityWarning: 'सुरक्षा चेतावणी',
    flaggedHighRisk: 'ही लिंक उच्च धोका म्हणून चिन्हांकित केली आहे.',
    reason: 'कारण',
    goBack: 'मागे जा (शिफारस केलेले)',
    proceed: 'तरीही पुढे जा',
    safeModeOn: 'सेफ मोड चालू आहे. असुरक्षित नेव्हिगेशन अवरोधित आहे.',
    analyzingSender: 'प्रेषकाचे विश्लेषण करत आहे...',
    checkingReputation: 'डोमेन reputation तपासत आहे...',
    scanningLinks: 'लिंक स्कॅन करत आहे...',
    scanningAttachments: 'मालवेअरसाठी अटॅचमेंट स्कॅन करत आहे...',
    verifyingSignatures: 'सुरक्षा स्वाक्षऱ्या पडताळत आहे...',
    safeEmail: 'सुरक्षित ईमेल',
    suspiciousActivity: 'संशयास्पद क्रियाकलाप',
    noThreats: 'कोणतेही धोके आढळले नाहीत',
    scanError: '⚠ सुरक्षा स्कॅन त्रुटी. कृपया पुन्हा प्रयत्न करा.',
    tip_urgency: ' खोटे संदेश तुम्हाला घाबरवण्यासाठी घाई करतात जेणेकरून तुम्ही विचार न करता क्लिक कराल.',
    tip_brand: ' खऱ्या कंपन्या कधीही ईमेल लिंकद्वारे लॉगिन करण्यास सांगत नाहीत.',
    tip_suspicious_link: ' फिशिंग साइट्स अनेकदा लोगोसी नकल करतात पण वेगळ्या वेब पत्त्याचा वापर करतात.',
    tip_general: ' क्लिक करण्यापूर्वी नेहमी लिंकवर होवर करून खरा पत्ता पहा.',
    learn_why: 'का ते शिका',
    learn_more: 'हे संकट समजून घेण्यासाठी क्लिक करा'
  }
};

let currentLang = 'en';
let safeModeEnabled = false;

// Initialize Preferences (Language & Safe Mode)
function loadPreferences() {
  chrome.storage.sync.get(['phishscan_language', 'phishscan_safemode'], (result) => {
    if (result.phishscan_language) currentLang = result.phishscan_language;
    if (result.phishscan_safemode === true) safeModeEnabled = true;
  });
}

// Helper for Translation
function t(key) {
  return TRANSLATIONS[currentLang][key] || TRANSLATIONS['en'][key];
}

function showConfirmationModal(url, reason) {
  // Re-check preferences just in case
  loadPreferences();

  const existingModal = document.querySelector('#phishscan-confirmation-root');
  if (existingModal) existingModal.remove();

  const host = document.createElement('div');
  host.id = 'phishscan-confirmation-root';
  document.body.appendChild(host);

  const shadow = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = createModalStyles();
  shadow.appendChild(style);

  const overlay = document.createElement('div');
  overlay.className = 'phishscan-modal-overlay';

  const proceedButtonHtml = safeModeEnabled
    ? '' // Completely REMOVE proceed button in Safe Mode
    : `<button class="phishscan-btn phishscan-btn-danger" id="phishscan-proceed">${t('proceed')}</button>`;

  const safeModeMessage = safeModeEnabled
    ? `<p style="margin-top: 12px; font-size: 12px; color: #9ca3af; font-weight: 500;">🔒 ${t('safeModeOn')}</p>`
    : '';

  overlay.innerHTML = `
    <div class="phishscan-modal-content">
      <span class="phishscan-warning-icon">⛔</span>
      <h2 class="phishscan-title">${t('securityWarning')}</h2>
      <p class="phishscan-message">
        <strong>${t('flaggedHighRisk')}</strong><br>
        ${t('reason')}: ${reason}
      </p>
      <div class="phishscan-url">${url}</div>
      
      <div class="phishscan-actions">
        <button class="phishscan-btn phishscan-btn-safe" id="phishscan-go-back">
          ${t('goBack')}
        </button>
        ${proceedButtonHtml}
      </div>
      ${safeModeMessage}
    </div>
  `;

  shadow.appendChild(overlay);

  // Handlers
  const backBtn = overlay.querySelector('#phishscan-go-back');
  const proceedBtn = overlay.querySelector('#phishscan-proceed');

  // Focus on Back Button for accessibility (and safety)
  if (backBtn) {
    backBtn.onclick = () => host.remove();
    setTimeout(() => backBtn.focus(), 50);
  }

  if (proceedBtn) {
    proceedBtn.onclick = () => {
      host.remove();
      window.open(url, '_blank');
    };
  }
}

function applyHoverProtections(emailNode, analysis) {
  const links = emailNode.querySelectorAll('a');

  links.forEach(link => {
    // 1. Contextual Highlight
    const parentBlock = link.closest('div, p, li') || link.parentElement;
    if (parentBlock && !parentBlock.hasAttribute('data-phishscan-context')) {
      parentBlock.setAttribute('data-phishscan-context', 'true');
      parentBlock.style.backgroundColor = 'rgba(252, 232, 230, 0.3)';
      parentBlock.style.borderLeft = '3px solid #f28b82';
      parentBlock.style.paddingLeft = '8px';
      parentBlock.style.borderRadius = '0 4px 4px 0';
    }

    // 2. Smart Indicator
    if (!link.nextElementSibling || !link.nextElementSibling.classList.contains('phishscan-indicator')) {
      const badge = document.createElement('span');
      badge.className = 'phishscan-indicator';
      badge.textContent = t('suspicious'); // Translated
      badge.style.cssText = `
        display: inline-block;
        font-size: 11px;
        font-weight: 500;
        color: #c5221f;
        background: #fce8e6;
        border: 1px solid #f28b82;
        border-radius: 12px;
        padding: 0 6px;
        margin-left: 4px;
        vertical-align: middle;
        cursor: help;
        font-family: 'Google Sans', Roboto, Arial, sans-serif;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
      `;
      link.parentNode.insertBefore(badge, link.nextSibling);

      badge.addEventListener('mouseenter', (e) => showRiskTooltip(link, analysis));
      badge.addEventListener('mouseleave', hideRiskTooltip);
    }

    // 3. Link Styling
    link.style.borderBottom = '2px dotted #d93025';
    link.style.textDecoration = 'none';
    link.style.color = '#d93025';

    // 4. Listeners
    link.addEventListener('mouseenter', (e) => showRiskTooltip(e.target, analysis));
    link.addEventListener('mouseleave', hideRiskTooltip);
    link.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showConfirmationModal(link.href, analysis.reasons[0] || t('highRisk'));
    });
  });
}

function showRiskTooltip(targetEl, analysis) {
  if (scanTooltip) scanTooltip.remove();

  scanTooltip = document.createElement('div');
  scanTooltip.id = 'phishscan-tooltip';

  const riskColor = analysis.riskLevel === 'HIGH' ? '#d93025' : '#f9ab00';
  const riskTitle = analysis.riskLevel === 'HIGH' ? t('highRisk') : t('suspiciousLink'); // Translated
  const reasonsList = analysis.reasons.map(r => `<li style="margin-bottom: 4px;">${r}</li>`).join('');

  scanTooltip.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #f1f3f4;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 18px;">🛡️</span>
        <span style="font-weight: 600; color: ${riskColor}; font-size: 14px;">${riskTitle}</span>
      </div>
      <span style="background: ${riskColor}; color: white; font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px;">${analysis.riskScore}% ${t('riskScore')}</span>
    </div>
    
    <div style="margin-bottom: 12px;">
      <ul style="margin: 0; padding-left: 16px; font-size: 12px; color: #3c4043; line-height: 1.5; list-style-type: disc;">
        ${reasonsList}
      </ul>
    </div>

    <div style="font-size: 11px; color: #5f6368; margin-top: 8px; font-style: italic; border-top: 1px solid #f1f3f4; padding-top: 8px;">
      ${t('flaggedMsg')}
    </div>
  `;

  scanTooltip.style.cssText = `
    position: absolute;
    background: #ffffff;
    color: #202124;
    padding: 16px;
    border-radius: 8px;
    width: 300px;
    z-index: 99999;
    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    border: 1px solid #e0e0e0;
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    animation: phishscan-fade-in 0.15s ease-out;
    pointer-events: none; 
    text-align: left;
  `;

  document.body.appendChild(scanTooltip);

  const rect = targetEl.getBoundingClientRect();
  const top = rect.bottom + window.scrollY + 10;
  const left = rect.left + window.scrollX;

  scanTooltip.style.top = top + 'px';
  scanTooltip.style.left = left + 'px';

  if (!document.getElementById('phishscan-anim-style')) {
    const style = document.createElement('style');
    style.id = 'phishscan-anim-style';
    style.textContent = `@keyframes phishscan-fade-in { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: translateY(0); } }`;
    document.head.appendChild(style);
  }
}

function hideRiskTooltip() {
  if (scanTooltip) {
    scanTooltip.remove();
    scanTooltip = null;
  }
}

// Start
loadPreferences(); // Load prefs first
init();
