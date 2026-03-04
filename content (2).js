// Prevent multiple executions of this script
if (window.phishScanLoaded) {
  // console.log('PhishScan already loaded, skipping...');
} else if (window.location.href.startsWith('chrome://') || window.location.href.startsWith('about:') || window.location.href.startsWith('edge://') || window.location.hostname === 'mail.google.com') {
  // Skip restricted pages and Gmail (handled by gmail_scanner.js)
} else {
  window.phishScanLoaded = true;


  // Configuration
  const SCAN_BATCH_SIZE = 6; // Batch size for API calls (balanced speed)
  const SCAN_DELAY = 150; // ms between batches
  const DEBOUNCE_DELAY = 1000; // ms for DOM change debouncing
  const API_TIMEOUT = 7000; // 7 second timeout for API calls
  const MAX_LINKS_PER_PAGE = 30; // Hard cap on links to scan per page
  const MAX_FORMS_PER_PAGE = 5; // Hard cap on forms to scan per page

  // Cache for processed URLs to avoid re-scanning
  const processedUrls = new Set();
  let scanInProgress = false;
  let observer = null;
  let rateLimitReached = false;

  // Safe Mode state (synced with storage)
  let safeModeEnabled = false;

  // Initialize Safe Mode state
  chrome.storage.sync.get(['phishscan_safemode'], (result) => {
    safeModeEnabled = result.phishscan_safemode === true;
  });

  // Listen for Safe Mode changes
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'sync' && changes.phishscan_safemode) {
      safeModeEnabled = changes.phishscan_safemode.newValue === true;
    }
  });

  // Test phishing URLs for demonstration (including some real ones from the feed)
  const TEST_PHISHING_URLS = [
    'example-phishing-site.com',
    'fake-login-page.com',
    'malicious-download.net',
    'fake-phishing-form.com',
    'phishing-test.com',
    'malicious-site.org',
    'fake-bank-login.com',
    'steal-password.net',
    'fake-paypal.com',
    'malware-download.com',
    'auspostac.world',
    'auspostac.world/index.html',
    'fake-auspost.com',
    'phishing-auspost.net',
    'malicious-auspost.org',
    // Real URLs from the OpenPhish feed for testing
    'meta-maskloig.godaddysites.com',
    'litebluelogin-gov.com',
    'netflix-web.vercel.app',
    'connect-ledger-login.typedream.app',
    'walletconnect-website.vercel.app',
    'mettusmask_lodin.godaddysites.com',
    'schwabprotection.com',
    'coinbaselogindesk.blogspot.com.ee',
    'kreken_x_logins.godaddysites.com',
    'sgbybabit.cc',
    'upohold-logiinus.godaddysites.com',
    'trezoriosuite.m-pages.com',
    'gnnnin_1o-giin.godaddysites.com',
    'publictrezzorstart.m-pages.com',
    'steamcomunnitty.cc',
    'bradescard.express-k.com',
    'help-extension-coinbase-chrome.typedream.app',
    'ebays.663shoppingsvip.xyz',
    'secure-id-controll.com',
    'gemminnees_usaloogaan.godaddysites.com',
    'private-user-support-center.io.vn',
    'amazon-clone-amber-mu.vercel.app',
    'netflix-web.vercel.app',
    'meta_-mask_-logi.godaddysites.com',
    'trezor.en-safewallets.com'
  ];

  // Safe domains that should never be flagged
  const SAFE_DOMAINS = [
    'google.com', 'google.co.uk', 'google.ca', 'google.com.au',
    'microsoft.com', 'microsoft.co.uk', 'microsoft.ca',
    'github.com', 'github.io', 'githubusercontent.com',
    'apple.com', 'icloud.com', 'me.com',
    'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'youtube.com', 'reddit.com',
    'stackoverflow.com', 'wikipedia.org', 'wikimedia.org',
    'mozilla.org', 'firefox.com', 'chrome.com',
    'cloudflare.com', 'fastly.com', 'akamai.com',
    'wordpress.com', 'tumblr.com', 'medium.com',
    'netflix.com', 'spotify.com', 'discord.com',
    'slack.com', 'zoom.us', 'teams.microsoft.com',
    'dropbox.com', 'box.com', 'onedrive.live.com',
    'paypal.com', 'stripe.com', 'square.com',
    'bankofamerica.com', 'wellsfargo.com', 'chase.com',
    'usps.com', 'fedex.com', 'ups.com',
    'weather.com', 'accuweather.com', 'weather.gov',
    'irs.gov', 'ssa.gov', 'usps.gov',
    'whitehouse.gov', 'congress.gov', 'supremecourt.gov'
  ];

  // Suspicious Patterns for Fallback Logic
  const IP_REGEX = /^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}/;
  const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'confirm', 'pay', 'bonus', 'free', 'gift', 'prize', 'urgent', 'suspend',
    // Brand keywords often used in phishing (add more as needed)
    'netflix', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'whatsapp', 'ledger', 'trezor', 'metamask', 'binance', 'coinbase', 'trustwallet'
  ];
  const SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.info', '.site', '.live', '.gq', '.tk', '.ml', '.ga', '.cf', '.buzz', '.cn', '.vip', '.work']; // Common abuse TLDs

  // Heuristic Risk Scoring
  function calculateRiskScore(url) {
    let score = 0;
    const reasons = [];
    const normalizedUrl = normalizeUrl(url);
    try {
      const urlObj = new URL(normalizedUrl);
      const hostname = urlObj.hostname.toLowerCase();

      // 1. Check for IP-based URL
      if (IP_REGEX.test(url)) {
        score += 50;
        reasons.push('IP-based URL detected (high risk)');
      }

      // 2. Check for suspicious keywords in hostname or path
      let keywordCount = 0;
      SUSPICIOUS_KEYWORDS.forEach(keyword => {
        if (normalizedUrl.includes(keyword)) {
          keywordCount++;
        }
      });
      if (keywordCount > 0) {
        score += 10 * keywordCount;
        reasons.push(`Contains suspicious keywords (${keywordCount})`);
      }

      // 3. Check for suspicious TLDs
      const isSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
      if (isSuspiciousTLD) {
        score += 20;
        reasons.push('Suspicious Top-Level Domain (TLD)');
      }

      // 4. URL Length (Extremely long URLs are often phishing)
      if (url.length > 75) {
        score += 10;
        reasons.push('Unusually long URL');
      }

      // 5. Subdomain count
      const dotCount = (hostname.match(/\./g) || []).length;
      if (dotCount > 3) {
        score += 15;
        reasons.push('Excessive subdomains');
      }
    } catch (e) {
      console.warn('Error calculating risk score:', e);
    }

    return { score, reasons };
  }

  // Track URL scan results for tooltips and display
  const urlScanResults = new Map();

  // Multilingual translation system (Hindi, Gujarati, English)
  const translations = {
    en: {
      unsafeLink: '⚠️ Unsafe Link',
      maliciousConfirmed: '⚠️ Malicious URL Confirmed!',
      verifiedSafe: '✅ Verified Safe',
      detection: '🚨 Detection',
      riskLevel: '🎯 Risk Level',
      suspiciousPatterns: '⚠️ Suspicious Patterns',
      shortenedUrl: '🔗 Shortened URL',
      original: 'Original',
      expanded: 'Expanded',
      vtAnalysis: '📊 VirusTotal Analysis',
      enginesDetected: 'Engines Found',
      enginesFlagged: 'Engines Flagged',
      threatLabels: '• Threat Labels',
      newDomain: '• 🆕 New Domain Found!',
      daysOld: 'days old',
      highRisk: 'High Risk',
      lastScan: '• Last Scan',
      warningMsg: '⚠️ Warning: This URL has been flagged as malicious. Do not click this link!',
      safeDomain: 'Safe Domain (Whitelisted)',
      clickToView: '• View Full Report: Click to see detailed analysis',
      expandedUrl: '🔗 Expanded URL',
      rateLimited: '⚠️ Scan Incomplete: API rate limit reached.',
      threatsDetected: (count) => `⚠️ ${count} malicious link${count > 1 ? 's' : ''} detected`,
      noLinksFound: 'ℹ️ No links found on this page',
      pageSafe: (count) => `✅ Page appears safe — ${count} link${count > 1 ? 's' : ''} scanned`
    },
    hi: {
      unsafeLink: '⚠️ असुरक्षित लिंक',
      maliciousConfirmed: '⚠️ दुर्भावनापूर्ण URL की पुष्टि की गई!',
      verifiedSafe: '✅ सत्यापित सुरक्षित',
      detection: '🚨 पहचान',
      riskLevel: '🎯 जोखिम स्तर',
      suspiciousPatterns: '⚠️ संदिग्ध पैटर्न',
      shortenedUrl: '🔗 छोटा किया गया URL',
      original: 'मूल',
      expanded: 'विस्तारित',
      vtAnalysis: '📊 VirusTotal विश्लेषण',
      enginesDetected: 'इंजन मिले',
      enginesFlagged: 'इंजन ने चेतावनी दी',
      threatLabels: '• खतरा लेबल',
      newDomain: '• 🆕 नया डोमेन मिला!',
      daysOld: 'दिन पुराना',
      highRisk: 'उच्च जोखिम',
      lastScan: '• अंतिम स्कैन',
      warningMsg: '⚠️ चेतावनी: इस URL को दुर्भावनापूर्ण के रूप में चिह्नित किया गया है। इस लिंक पर क्लिक न करें!',
      safeDomain: 'सुरक्षित डोमेन (श्वेतसूचीबद्ध)',
      clickToView: '• पूरी रिपोर्ट देखें: विस्तृत विश्लेषण देखने के लिए क्लिक करें',
      expandedUrl: '🔗 विस्तारित URL',
      rateLimited: '⚠️ स्कैन अधूरा: API दर सीमा पहुंच गई।',
      threatsDetected: (count) => `⚠️ ${count} दुर्भावनापूर्ण लिंक${count > 1 ? ' पाए गए' : ' पाया गया'}`,
      noLinksFound: 'ℹ️ इस पृष्ठ पर कोई लिंक नहीं मिला',
      pageSafe: (count) => `✅ पृष्ठ सुरक्षित लगता है — ${count} लिंक${count > 1 ? ' स्कैन किए गए' : ' स्कैन किया गया'}`
    },
    gu: {
      unsafeLink: '⚠️ અસુરક્ષિત લિંક',
      maliciousConfirmed: '⚠️ દુર્ભાવનાપૂર્ણ URL ની પુષ્ટિ કરી!',
      verifiedSafe: '✅ ચકાસાયેલ સુરક્ષિત',
      detection: '🚨 ઓળખ',
      riskLevel: '🎯 જોખમ સ્તર',
      suspiciousPatterns: '⚠️ શંકાસ્પદ પેટર્ન',
      shortenedUrl: '🔗 ટૂંકું કરેલું URL',
      original: 'મૂળ',
      expanded: 'વિસ્તૃત',
      vtAnalysis: '📊 VirusTotal વિશ્લેષણ',
      enginesDetected: 'એન્જિન મળ્યા',
      enginesFlagged: 'એન્જિન ચેતવણી આપી',
      threatLabels: '• ખતરાના લેબલ',
      newDomain: '• 🆕 નવું ડોમેન મળ્યું!',
      daysOld: 'દિવસ જૂનું',
      highRisk: 'ઉચ્ચ જોખમ',
      lastScan: '• છેલ્લું સ્કેન',
      warningMsg: '⚠️ ચેતવણી: આ URL ને દુર્ભાવનાપૂર્ણ તરીકે ચિહ્નિત કરવામાં આવ્યું છે. આ લિંક પર ક્લિક કરશો નહીં!',
      safeDomain: 'સુરક્ષિત ડોમેન (વ્હાઇટલિસ્ટેડ)',
      clickToView: '• સંપૂર્ણ રિપોર્ટ જુઓ: વિગતવાર વિશ્લેષણ જોવા માટે ક્લિક કરો',
      expandedUrl: '🔗 વિસ્તૃત URL',
      rateLimited: '⚠️ સ્કેન અધૂરું: API દર મર્યાદા પહોંચી ગઈ.',
      threatsDetected: (count) => `⚠️ ${count} દુર્ભાવનાપૂર્ણ લિંક${count > 1 ? ' મળી' : ' મળી'}`,
      noLinksFound: 'ℹ️ આ પૃષ્ઠ પર કોઈ લિંક મળી નથી',
      pageSafe: (count) => `✅ પૃષ્ઠ સુરક્ષિત લાગે છે — ${count} લિંક${count > 1 ? ' સ્કેન કરવામાં આવ્યા' : ' સ્કેન કરવામાં આવ્યું'}`
    },
    mr: {
      unsafeLink: '⚠️ असुरक्षित लिंक',
      maliciousConfirmed: '⚠️ दुर्भावनायुक्त URL ची पुष्टी झाली!',
      verifiedSafe: '✅ सत्यापित सुरक्षित',
      detection: '🚨 ओळख',
      riskLevel: '🎯 जोखीम स्तर',
      suspiciousPatterns: '⚠️ संशयास्पद नमुने',
      shortenedUrl: '🔗 लहान केलेली URL',
      original: 'मूळ',
      expanded: 'विस्तारित',
      vtAnalysis: '📊 VirusTotal विश्लेषण',
      enginesDetected: 'इंजिन आढळले',
      enginesFlagged: 'इंजिनने इशारा दिला',
      threatLabels: '• धोक्याचे लेबल',
      newDomain: '• 🆕 नवीन डोमेन आढळले!',
      daysOld: 'दिवस जुने',
      highRisk: 'उच्च धोका',
      lastScan: '• शेवटचे स्कॅन',
      warningMsg: '⚠️ चेतावणी: ही URL दुर्भावनायुक्त म्हणून चिन्हांकित केली आहे. या लिंकवर क्लिक करू नका!',
      safeDomain: 'सुरक्षित डोमेन (व्हाइटलिस्ट केलेले)',
      clickToView: '• पूर्ण अहवाल पहा: तपशीलवार विश्लेषण पाहण्यासाठी क्लिक करा',
      expandedUrl: '🔗 विस्तारित URL',
      rateLimited: '⚠️ स्कॅन अपूर्ण: API दर मर्यादा गाठली.',
      threatsDetected: (count) => `⚠️ ${count} दुर्भावनायुक्त लिंक${count > 1 ? ' आढळल्या' : ' आढळली'}`,
      noLinksFound: 'ℹ️ या पृष्ठावर कोणतीही लिंक आढळली नाही',
      pageSafe: (count) => `✅ पृष्ठ सुरक्षित वाटते — ${count} लिंक${count > 1 ? ' स्कॅन केल्या' : ' स्कॅन केली'}`
    }
  };

  // Styles for the confirmation modal
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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .phishscan-modal-content {
      background: white;
      border-radius: 12px;
      padding: 24px;
      width: 90%;
      max-width: 450px;
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
      margin-bottom: 16px;
      display: block;
    }
    .phishscan-title {
      color: #dc2626;
      font-size: 20px;
      font-weight: 700;
      margin: 0 0 12px 0;
    }
    .phishscan-message {
      color: #374151;
      font-size: 15px;
      line-height: 1.5;
      margin-bottom: 20px;
    }
    .phishscan-url {
      background: #f3f4f6;
      padding: 8px 12px;
      border-radius: 6px;
      font-family: monospace;
      color: #dc2626;
      font-size: 13px;
      margin-bottom: 24px;
      word-break: break-all;
      border: 1px solid #e5e7eb;
    }
    .phishscan-actions {
      display: flex;
      gap: 12px;
      justify-content: center;
    }
    .phishscan-btn {
      padding: 10px 20px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      border: none;
      transition: transform 0.1s;
    }
    .phishscan-btn:active {
      transform: scale(0.98);
    }
    .phishscan-btn-safe {
      background: #10b981;
      color: white;
      flex: 1;
    }
    .phishscan-btn-danger {
      background: transparent;
      color: #6b7280;
      border: 1px solid #d1d5db;
    }
    .phishscan-btn-danger:hover {
      background: #f3f4f6;
      color: #374151;
    }
  `;
  }

  // Show confirmation modal using Shadow DOM
  // Show confirmation modal using Shadow DOM
  function showConfirmationModal(url, reason = '', virustotalData = null) {
    // Remove existing modal if any
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

    const domain = new URL(url).hostname;

    // Customizable risk message based on reason (simplified)
    let riskMessage = "This link has been flagged as suspicious.";
    let riskTitle = "STOP! Unsafe link detected";

    // Simple heuristic for message logging (can be expanded)
    if (reason.toLowerCase().includes('phishing') || reason.toLowerCase().includes('social')) {
      riskMessage = "This site may try to steal your account password or personal information.";
    } else if (reason.toLowerCase().includes('malware') || reason.toLowerCase().includes('virus')) {
      riskMessage = "This site may try to install harmful software on your device.";
    } else {
      riskMessage = "This link appears unsafe. It is better to avoid it.";
    }

    overlay.innerHTML = `
    <div class="phishscan-modal-content">
      <span class="phishscan-warning-icon">⛔</span>
      <h2 class="phishscan-title">${riskTitle}</h2>
      <p class="phishscan-message">
        <strong>${riskMessage}</strong>
        <br><br>
        <span style="color: #6b7280; font-size: 0.9em;">Domain: ${domain}</span>
      </p>
      
      <div class="phishscan-actions">
        <button class="phishscan-btn phishscan-btn-safe" id="phishscan-go-back">
          Go Back (Recommended)
        </button>
        ${!safeModeEnabled ? `
        <button class="phishscan-btn phishscan-btn-danger" id="phishscan-proceed">
          Proceed Anyway (Unsafe)
        </button>
        ` : ''}
      </div>
      ${safeModeEnabled ? '<p style="margin-top: 12px; font-size: 12px; color: #9ca3af;">Safe Mode is ON. Unsafe navigation is blocked.</p>' : ''}
    </div>
  `;

    shadow.appendChild(overlay);

    // Focus management
    const backBtn = overlay.querySelector('#phishscan-go-back');
    const proceedBtn = overlay.querySelector('#phishscan-proceed');

    if (backBtn) backBtn.focus();

    // Event handlers
    if (backBtn) {
      backBtn.onclick = () => {
        host.remove();
      };
    }

    if (proceedBtn) {
      proceedBtn.onclick = () => {
        // Last ditch confirmation? No, simple click is enough for "Proceed Anyway" if safe mode is off.
        host.remove();
        window.location.href = url;
      };
    }

    // Close on specific key press (ESC)
    const handleKeydown = (e) => {
      if (e.key === 'Escape') {
        host.remove();
        document.removeEventListener('keydown', handleKeydown);
      }
    };
    document.addEventListener('keydown', handleKeydown);
  }

  function highlightElement(el, reason = '', isShortened = false, resolvedUrl = null, virustotalData = null) {
    if (el.hasAttribute('data-phishscan-malicious')) return; // Already highlighted as malicious

    // Remove any existing clean markers
    if (el.hasAttribute('data-phishscan-clean')) {
      el.removeAttribute('data-phishscan-clean');
      const existingIndicator = el.querySelector('.phishscan-clean-indicator');
      if (existingIndicator) existingIndicator.remove();
    }

    el.style.border = '2px solid #dc3545';
    el.style.backgroundColor = 'rgba(220, 53, 69, 0.1)'; // Light red background
    el.setAttribute('data-phishscan-malicious', 'true');
    el.classList.add('phishscan-malicious-link');

    // Intercept clicks on malicious links
    el.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showConfirmationModal(el.href, reason, virustotalData);
    }, true);

    // Store scan result for detailed tooltips
    if (virustotalData) {
      urlScanResults.set(el.href, { type: 'malicious', data: virustotalData, isShortened, resolvedUrl });
    }

    // Build tooltip text using translations
    let tooltipText = `${t('maliciousConfirmed')}\n\n${t('detection')}: ${reason}`;

    if (isShortened && resolvedUrl) {
      tooltipText += `\n\n${t('shortenedUrl')}:\n${t('original')}: ${el.href}\n${t('expanded')}: ${resolvedUrl}`;
    }

    if (virustotalData) {
      if (virustotalData.positives !== undefined) {
        // Safe check for total to avoid division by zero or undefined
        if (virustotalData.positives > 0) {
          tooltipText += `\n\n${t('vtAnalysis')}: ${t('highRisk')}`;
        } else {
          tooltipText += `\n\n${t('vtAnalysis')}: ${t('verifiedSafe')}`;
        }
      }

      if (virustotalData.scanDate) {
        tooltipText += `\n${t('lastScan')}: ${new Date(virustotalData.scanDate * 1000).toLocaleDateString()}`;
      }

      if (virustotalData.permalink) {
        tooltipText += `\n${t('clickToView')}`;
      }
    }

    tooltipText += `\n\n${t('warningMsg')}`;

    // Set native tooltip
    el.title = tooltipText;

    // Add visual label
    const label = document.createElement('span');
    label.className = 'phishscan-malicious-label';
    label.innerHTML = t('unsafeLink');
    label.style.cssText = `
      background-color: #fee2e2; 
      color: #991b1b; 
      font-size: 11px; 
      font-weight: bold; 
      padding: 2px 6px; 
      border-radius: 4px; 
      border: 1px solid #f87171; 
      margin-left: 6px; 
      vertical-align: middle;
      display: inline-block;
      white-space: nowrap;
      font-family: sans-serif;
      box-shadow: 0 1px 2px rgba(0,0,0,0.05);
      z-index: 1000;
    `;

    // Click interceptor for the label
    label.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showConfirmationModal(el.href, reason, virustotalData);
    }, true);

    // Ensure the label is clickable? No, we want the link to be clickable (to trigger interception).
    // If user clicks label, it might not trigger link click if appended outside or if bubbling weirdly.
    // If we append to 'el', clicking label bubbles to 'el', triggering our interceptor. Good.
    el.appendChild(label);
  }

  // Mark clean/safe URLs with green checkmark
  function markCleanElement(el, reason = '', isShortened = false, resolvedUrl = null, virustotalData = null) {
    // Don't override malicious markers
    if (el.hasAttribute('data-phishscan-malicious')) return;

    // Don't mark if already marked as clean (unless we have new data)
    if (el.hasAttribute('data-phishscan-clean') && !virustotalData) return;

    el.setAttribute('data-phishscan-clean', 'true');
    el.classList.add('phishscan-clean-link');

    // Store scan result
    if (virustotalData) {
      urlScanResults.set(el.href, { type: 'clean', data: virustotalData, isShortened, resolvedUrl });
    }

    // Enhanced tooltip for clean URLs
    let tooltipText = `${t('verifiedSafe')}\n\n✓ ${reason}`;

    if (isShortened && resolvedUrl) {
      tooltipText += `\n\n${t('shortenedUrl')}:\n${t('original')}: ${el.href}\n${t('expanded')}: ${resolvedUrl}`;
    }

    if (virustotalData && virustotalData.total > 0) {
      tooltipText += `\n\n${t('vtAnalysis')}:\n• Clean: ${virustotalData.positives}/${virustotalData.total} ${t('enginesFlagged')}`;
      if (virustotalData.scanDate) {
        tooltipText += `\n${t('lastScan')}: ${new Date(virustotalData.scanDate * 1000).toLocaleDateString()}`;
      }
      if (virustotalData.permalink) {
        tooltipText += `\n${t('clickToView')}`;
      }
    }

    // Add subtle green checkmark indicator
    const checkmark = document.createElement('span');
    checkmark.className = 'phishscan-clean-indicator';
    checkmark.textContent = '✅';
    checkmark.style.marginLeft = '5px';
    checkmark.style.fontSize = '12px';
    checkmark.style.opacity = '0.7';
    checkmark.style.cursor = 'help';
    checkmark.title = tooltipText;

    // Set tooltip on the link itself
    el.title = tooltipText;

    // Only add checkmark if not already present
    if (!el.querySelector('.phishscan-clean-indicator')) {
      el.appendChild(checkmark);
    }
  }

  // Enhanced tooltip for shortened URLs on hover (works with mouseover)
  function setupShortenedUrlTooltip(el, resolvedUrl) {
    if (!resolvedUrl || resolvedUrl === el.href) return;

    el.addEventListener('mouseenter', function () {
      // Create or update tooltip
      let tooltip = document.getElementById('phishscan-url-tooltip');
      if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'phishscan-url-tooltip';
        tooltip.style.cssText = `
          position: absolute;
          background: #2d3748;
          color: white;
          padding: 8px 12px;
          border-radius: 6px;
          font-size: 12px;
          z-index: 10000;
          max-width: 400px;
          word-break: break-all;
          box-shadow: 0 4px 6px rgba(0,0,0,0.3);
          pointer-events: none;
        `;
        document.body.appendChild(tooltip);
      }

      tooltip.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 4px;">${t('expandedUrl')}:</div>
        <div style="color: #90cdf4;">${resolvedUrl}</div>
      `;

      // Position tooltip near the link
      const rect = el.getBoundingClientRect();
      tooltip.style.top = (rect.bottom + window.scrollY + 5) + 'px';
      tooltip.style.left = (rect.left + window.scrollX) + 'px';
    });

    el.addEventListener('mouseleave', function () {
      const tooltip = document.getElementById('phishscan-url-tooltip');
      if (tooltip) {
        tooltip.remove();
      }
    });
  }

  // Enhanced URL normalization - remove tracking params and ensure proper scheme
  function normalizeUrl(url) {
    if (!url) return '';

    try {
      // Create URL object to properly parse
      let urlObj;
      try {
        urlObj = new URL(url);
      } catch (e) {
        // If URL is relative, make it absolute
        urlObj = new URL(url, window.location.href);
      }

      // Remove tracking parameters
      const trackingParams = [
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid', 'gclid', 'msclkid', 'ref', 'source', 'campaign', 'medium',
        'term', 'content', 'clickid', 'affiliate', 'partner', 'referrer'
      ];

      trackingParams.forEach(param => {
        urlObj.searchParams.delete(param);
      });

      // Ensure HTTPS scheme
      if (urlObj.protocol === 'http:') {
        urlObj.protocol = 'https:';
      }

      // Remove fragments
      urlObj.hash = '';

      // Normalize hostname (lowercase, remove www)
      urlObj.hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');

      return urlObj.toString();
    } catch (e) {
      console.error('Error normalizing URL:', url, e);
      return url;
    }
  }

  // Check if domain is in safe list
  function isSafeDomain(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');

      // Check exact match
      if (SAFE_DOMAINS.includes(hostname)) {
        return true;
      }

      // Check subdomain matches
      for (const safeDomain of SAFE_DOMAINS) {
        if (hostname.endsWith('.' + safeDomain)) {
          return true;
        }
      }

      return false;
    } catch (e) {
      return false;
    }
  }

  // Check if URL is shortened
  async function isShortenedURL(url) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'IS_SHORTENED_URL',
        url: url
      });
      return response?.isShortened || false;
    } catch (e) {
      console.error('Error checking if URL is shortened:', e);
      return false;
    }
  }

  // Resolve shortened URL
  async function resolveShortenedURL(url) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'RESOLVE_SHORTENED_URL',
        url: url
      });
      return response?.resolvedUrl || url;
    } catch (e) {
      console.error('Error resolving shortened URL:', e);
      return url;
    }
  }

  // Google Safe Browsing API check
  async function checkSafeBrowsing(url) {
    try {
      // Get API key from background script
      const apiKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_SAFE_BROWSING_KEY' });
      const apiKey = apiKeyResponse?.key;

      if (!apiKey || apiKey.trim() === '') {
        console.log('No API key configured, skipping Safe Browsing check');
        return { malicious: false, reason: 'API key not configured' };
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);

      const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client: {
            clientId: 'phishscan-extension',
            clientVersion: '1.0'
          },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: url }]
          }
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        if (data.matches && data.matches.length > 0) {
          const threat = data.matches[0];
          return {
            malicious: true,
            reason: `Google Safe Browsing: ${threat.threatType}`,
            threatType: threat.threatType,
            platformType: threat.platformType
          };
        }
      } else if (response.status === 429) {
        // Rate limit exceeded
        rateLimitReached = true;
        return { malicious: false, reason: 'API rate limit exceeded', rateLimited: true };
      }
    } catch (e) {
      console.error('Safe Browsing API error:', e);
      if (e.name === 'AbortError') {
        return { malicious: false, reason: 'API request timeout' };
      }
    }

    return { malicious: false, reason: 'No threats detected' };
  }

  // VirusTotal API check
  async function checkVirusTotal(url) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'CHECK_VIRUSTOTAL',
        url: url
      });
      return response;
    } catch (e) {
      console.error('VirusTotal API error:', e);
      return { malicious: false, reason: 'VirusTotal: Network error' };
    }
  }

  // Improved fallback detection using OpenPhish database with better matching
  function checkOpenPhishDatabase(url, phishingSet) {
    if (!phishingSet || phishingSet.size === 0) {
      console.log('OpenPhish database is empty, using test URLs');
      // Fallback to test URLs if database is empty
      const testSet = new Set(TEST_PHISHING_URLS);
      return checkOpenPhishDatabaseInternal(url, testSet);
    }

    return checkOpenPhishDatabaseInternal(url, phishingSet);
  }

  function checkOpenPhishDatabaseInternal(url, phishingSet) {
    // First check if it's a safe domain
    if (isSafeDomain(url)) {
      console.log('URL is in safe domain list:', url);
      return { malicious: false, reason: 'Safe domain (whitelisted)' };
    }

    const normalizedUrl = normalizeUrl(url);
    const urlObj = new URL(normalizedUrl);
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    const domain = hostname.split('.').slice(-2).join('.'); // Get main domain (e.g., google.com from sub.google.com)

    console.log('Checking URL against phishing database:', {
      original: url,
      normalized: normalizedUrl,
      hostname: hostname,
      domain: domain,
      databaseSize: phishingSet.size
    });

    // Check exact match first (most precise)
    if (phishingSet.has(normalizedUrl)) {
      console.log('Exact match found in phishing database');
      return { malicious: true, reason: 'Exact match in phishing database' };
    }

    // Check hostname match (more precise than domain)
    if (phishingSet.has(hostname)) {
      console.log('Hostname match found in phishing database');
      return { malicious: true, reason: 'Hostname match in phishing database' };
    }

    // Check domain match (less precise, but still good)
    if (phishingSet.has(domain)) {
      console.log('Domain match found in phishing database');
      return { malicious: true, reason: 'Domain match in phishing database' };
    }

    // Check for broader matches (more flexible)
    for (const phishingUrl of phishingSet) {
      // Check if the phishing URL contains our hostname or domain
      if (phishingUrl.includes(hostname) || phishingUrl.includes(domain)) {
        console.log('Broad match found in phishing database:', phishingUrl);
        return { malicious: true, reason: 'Broad match in phishing database' };
      }

      // Check if our URL contains the phishing URL
      if (hostname.includes(phishingUrl) || domain.includes(phishingUrl)) {
        console.log('Reverse match found in phishing database:', phishingUrl);
        return { malicious: true, reason: 'Reverse match in phishing database' };
      }
    }

    console.log('No match found in phishing database');
    return { malicious: false, reason: 'No match in phishing database' };
  }

  // Main URL checking function with VirusTotal integration and shortened URL resolution
  async function checkUrlWithAPI(url) {
    if (!url) return { malicious: false, reason: 'No URL provided' };

    const normalizedUrl = normalizeUrl(url);
    console.log('Checking URL:', url, 'Normalized:', normalizedUrl);

    // Immediately trust known safe domains to avoid false positives
    if (isSafeDomain(normalizedUrl)) {
      return {
        malicious: false,
        reason: 'Safe domain (whitelisted)',
        originalUrl: url,
        resolvedUrl: null,
        isShortened: false,
        virustotalData: null
      };
    }

    // Check if already processed
    if (processedUrls.has(normalizedUrl)) {
      console.log('URL already processed:', normalizedUrl);
      return null;
    }

    processedUrls.add(normalizedUrl);

    // Check if URL is shortened
    const isShortened = await isShortenedURL(normalizedUrl);
    let finalUrl = normalizedUrl;
    let resolvedUrl = null;

    if (isShortened) {
      console.log('Detected shortened URL, resolving...');
      resolvedUrl = await resolveShortenedURL(normalizedUrl);
      finalUrl = resolvedUrl;

      if (resolvedUrl !== normalizedUrl) {
        console.log('Resolved shortened URL:', normalizedUrl, '→', resolvedUrl);

        // Check if resolved URL is already processed
        if (processedUrls.has(resolvedUrl)) {
          console.log('Resolved URL already processed:', resolvedUrl);
          return null;
        }
        processedUrls.add(resolvedUrl);
      }
    }

    // Check if APIs are configured
    const apiKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_SAFE_BROWSING_KEY' });
    const virusTotalKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_VIRUSTOTAL_KEY' });

    const safeBrowsingKeyConfigured = apiKeyResponse?.key && apiKeyResponse.key.trim() !== '';
    const virusTotalKeyConfigured = virusTotalKeyResponse?.key && virusTotalKeyResponse.key.trim() !== '';

    console.log('API keys configured:', { safeBrowsing: safeBrowsingKeyConfigured, virusTotal: virusTotalKeyConfigured });

    // First, try Google Safe Browsing API if configured
    if (safeBrowsingKeyConfigured) {
      const safeBrowsingResult = await checkSafeBrowsing(finalUrl);

      if (safeBrowsingResult.malicious) {
        console.log('Found malicious URL via Safe Browsing API:', finalUrl, 'Reason:', safeBrowsingResult.reason);
        return {
          ...safeBrowsingResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }
    }

    // Always try VirusTotal if configured (for both malicious and clean detection)
    let virusTotalResult = null;
    if (virusTotalKeyConfigured) {
      virusTotalResult = await checkVirusTotal(finalUrl);

      if (virusTotalResult.malicious) {
        console.log('Found malicious URL via VirusTotal:', finalUrl, 'Reason:', virusTotalResult.reason);
        return {
          ...virusTotalResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }
      // If VirusTotal says it's clean and has data, return clean result with data
      if (virusTotalResult.responseCode === 1 && virusTotalResult.total > 0) {
        console.log('URL verified clean by VirusTotal:', finalUrl);
        return {
          malicious: false,
          reason: virusTotalResult.reason || 'Verified safe by VirusTotal',
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened,
          virustotalData: virusTotalResult // Include full VirusTotal data for detailed view
        };
      }
    }

    // If APIs are not configured or didn't find anything, fall back to OpenPhish database AND heuristics
    if (!safeBrowsingKeyConfigured && !virusTotalKeyConfigured) {
      console.log('No API keys configured, checking heuristics and OpenPhish...');

      // 1. Check TEST_PHISHING_URLS (Always check these for demo/testing purposes)
      // This ensures the demo page always works even if the live feed is empty or different
      const testSet = new Set(TEST_PHISHING_URLS);
      const testResult = checkOpenPhishDatabase(finalUrl, testSet);
      if (testResult.malicious) {
        console.log('Found malicious URL via TEST SET:', finalUrl);
        return {
          ...testResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened,
          reason: 'Known phishing site (Test Database)'
        };
      }

      // 2. Check OpenPhish Feed
      const phishingList = await getPhishFeed();
      const phishingSet = new Set(phishingList);
      const openPhishResult = checkOpenPhishDatabase(finalUrl, phishingSet);

      if (openPhishResult.malicious) {
        console.log('Found malicious URL via OpenPhish database:', finalUrl, 'Reason:', openPhishResult.reason);
        return {
          ...openPhishResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }

      // 3. Check Local Heuristics (Risk Score)
      const heuristicData = calculateRiskScore(finalUrl);
      console.log('Heuristic analysis result:', finalUrl, heuristicData);

      // Lower threshold slightly for better detection in demo mode without API keys
      if (heuristicData.score >= 25) {
        console.log('Found malicious URL via Heuristics:', finalUrl, 'Score:', heuristicData.score);
        return {
          malicious: true,
          reason: `Suspicious patterns: ${heuristicData.reasons.join(', ')}`,
          riskScore: heuristicData.score,
          heuristicReasons: heuristicData.reasons,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }
    }




    // If we have VirusTotal data but URL wasn't in database, return clean with data
    if (virusTotalResult && virusTotalResult.responseCode === 0) {
      return {
        malicious: false,
        reason: virusTotalResult.reason || 'URL not in VirusTotal database',
        originalUrl: url,
        resolvedUrl: resolvedUrl,
        isShortened: isShortened,
        virustotalData: virusTotalResult
      };
    }

    console.log('URL check result for:', finalUrl, 'Safe');
    return {
      malicious: false,
      reason: 'No threats detected by any service',
      originalUrl: url,
      resolvedUrl: resolvedUrl,
      isShortened: isShortened,
      virustotalData: virusTotalResult || null
    };
  }

  async function getPhishFeed() {
    return new Promise((resolve) => {
      console.log('Requesting phishing feed from background script...');
      chrome.runtime.sendMessage({ type: 'GET_PHISH_FEED' }, (response) => {
        console.log('Phish feed response:', response);
        const openPhishUrls = response?.phishingList || [];
        console.log(`Received ${openPhishUrls.length} URLs from OpenPhish feed`);

        if (openPhishUrls.length === 0) {
          console.log('OpenPhish feed is empty, will use test URLs as fallback');
        } else {
          console.log('Sample URLs from feed:', openPhishUrls.slice(0, 5));
        }

        resolve(openPhishUrls);
      });
    });
  }

  async function getToggleState() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'GET_TOGGLE_STATE' }, (response) => {
        resolve(response?.enabled !== false);
      });
    });
  }

  // Enhanced batch processing for API calls (no global time cap, just gentle pacing)
  async function processBatch(elements, processFn) {
    const results = [];
    for (let i = 0; i < elements.length; i += SCAN_BATCH_SIZE) {
      const batch = elements.slice(i, i + SCAN_BATCH_SIZE);

      const batchPromises = batch.map(async (element) => {
        const result = await processFn(element);
        if (result) results.push(result);
      });

      await Promise.all(batchPromises);

      // Yield control to prevent blocking and respect API rate limits
      if (i + SCAN_BATCH_SIZE < elements.length) {
        await new Promise(resolve => setTimeout(resolve, SCAN_DELAY));
      }
    }
    return results;
  }

  // Debounced function to prevent excessive scanning
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

  // Main scanning function with enhanced detection
  async function scanPage() {
    if (scanInProgress) return;

    scanInProgress = true;

    try {
      console.log('Starting enhanced page scan with VirusTotal integration...');

      // Set scan-in-progress flag
      await chrome.storage.local.set({ phishscan_scanning: true });
      await chrome.storage.local.remove('phishscan_found');

      await loadLanguagePreferences(); // Ensure language is loaded before scanning
      const enabled = await getToggleState();
      if (!enabled) {
        await chrome.storage.local.set({ phishscan_scanning: false });
        scanInProgress = false;
        return;
      }

      // Clear processed URLs for fresh scan
      processedUrls.clear();

      const found = [];
      const cleanUrls = [];
      let totalScanned = 0;

      // Get all elements to scan (capped for speed)
      const allLinks = Array.from(document.querySelectorAll('a[href]'));
      const allForms = Array.from(document.querySelectorAll('form[action]'));
      const aTags = allLinks.slice(0, MAX_LINKS_PER_PAGE);
      const formTags = allForms.slice(0, MAX_FORMS_PER_PAGE);

      console.log(`Scanning ${aTags.length}/${allLinks.length} links, ${formTags.length}/${allForms.length} forms with enhanced detection`);

      // Process links in batches
      const linkResults = await processBatch(aTags, async (a) => {
        const url = a.href;
        if (url) {
          console.log('Processing link URL:', url);
          totalScanned++;
          const result = await checkUrlWithAPI(url);
          console.log('Link check result:', url, result);

          if (result) {
            if (result.malicious) {
              console.log('Found malicious link:', url, 'Reason:', result.reason);
              highlightElement(
                a,
                result.reason,
                result.isShortened,
                result.resolvedUrl,
                result.virustotalData || (result.positives !== undefined ? result : null)
              );

              // Set up tooltip for shortened URLs
              if (result.isShortened && result.resolvedUrl) {
                setupShortenedUrlTooltip(a, result.resolvedUrl);
              }

              return {
                url: result.originalUrl || url,
                reason: result.reason,
                threatType: result.threatType,
                isShortened: result.isShortened,
                resolvedUrl: result.resolvedUrl,
                virustotalData: result.virustotalData || (result.positives !== undefined ? result : null)
              };
            } else {
              // Mark as clean if we have VirusTotal data and no minor detections
              if (result.virustotalData && result.virustotalData.total > 0 && !result.virustotalData.minorDetections) {
                console.log('Marking clean link:', url);
                markCleanElement(
                  a,
                  result.reason,
                  result.isShortened,
                  result.resolvedUrl,
                  result.virustotalData
                );

                // Set up tooltip for shortened URLs
                if (result.isShortened && result.resolvedUrl) {
                  setupShortenedUrlTooltip(a, result.resolvedUrl);
                }

                cleanUrls.push({
                  url: result.originalUrl || url,
                  reason: result.reason,
                  virustotalData: result.virustotalData
                });
              }
            }
          }
        }
        return null;
      });

      // Process forms in batches
      const formResults = await processBatch(formTags, async (f) => {
        const url = f.action;
        if (url) {
          console.log('Processing form action URL:', url);
          totalScanned++;
          const result = await checkUrlWithAPI(url);
          console.log('Form check result:', url, result);

          if (result && result.malicious) {
            console.log('Found malicious form:', url, 'Reason:', result.reason);
            highlightElement(
              f,
              result.reason,
              result.isShortened,
              result.resolvedUrl,
              result.virustotalData || (result.positives !== undefined ? result : null)
            );

            return {
              url: result.originalUrl || url,
              reason: result.reason,
              threatType: result.threatType,
              isShortened: result.isShortened,
              resolvedUrl: result.resolvedUrl,
              virustotalData: result.virustotalData || (result.positives !== undefined ? result : null)
            };
          }
        }
        return null;
      });

      // Combine results
      const allResults = linkResults.filter(r => r !== null).concat(formResults.filter(r => r !== null));

      // Store results with scan statistics
      await chrome.storage.local.set({
        phishscan_found: allResults,
        phishscan_clean: cleanUrls,
        phishscan_total_scanned: totalScanned,
        phishscan_scanning: false,
        phishscan_rate_limited: rateLimitReached
      });

      // Update in-page banner so users see the result without opening the popup
      updatePageStatusBanner({
        totalScanned,
        threats: allResults.length,
        clean: cleanUrls.length,
        rateLimited: rateLimitReached
      });

      console.log(`Enhanced scan complete. Found ${allResults.length} threats:`, allResults);

      if (rateLimitReached) {
        console.warn('API rate limit reached during scan');
      }

    } catch (error) {
      console.error('Error during enhanced scan:', error);
      await chrome.storage.local.set({ phishscan_scanning: false });
    } finally {
      scanInProgress = false;
    }
  }

  // Debounced scan function for DOM changes
  const debouncedScan = debounce(scanPage, DEBOUNCE_DELAY);



  // Detect language from storage, page, or browser
  let cachedLanguage = null;
  function detectLanguage() {
    // Return cached language if available
    if (cachedLanguage) {
      return cachedLanguage;
    }

    // Check browser language as fallback
    const browserLang = navigator.language || navigator.userLanguage || 'en';
    const langCode = browserLang.split('-')[0].toLowerCase();

    // Check page language attribute
    const pageLang = document.documentElement.lang || '';
    const pageLangCode = pageLang.split('-')[0].toLowerCase();

    let detectedLang = 'en';

    // Priority: page lang > browser lang > default to English
    if (pageLangCode === 'hi' || pageLangCode === 'gu') {
      detectedLang = pageLangCode;
    } else if (langCode === 'hi' || langCode === 'gu') {
      detectedLang = langCode;
    }

    cachedLanguage = detectedLang;
    return detectedLang;
  }


  // Load language from chrome.storage with Promise support
  function loadLanguagePreferences() {
    return new Promise((resolve) => {
      chrome.storage.sync.get(['phishscan_language'], (result) => {
        if (result.phishscan_language && (result.phishscan_language === 'hi' || result.phishscan_language === 'gu' || result.phishscan_language === 'en')) {
          cachedLanguage = result.phishscan_language;
          // Refresh banner if it exists
          if (statusBannerEl) {
            chrome.storage.local.get(['phishscan_total_scanned', 'phishscan_found', 'phishscan_rate_limited', 'phishscan_clean'], (localResult) => {
              updatePageStatusBanner({
                totalScanned: localResult.phishscan_total_scanned || 0,
                threats: (localResult.phishscan_found || []).length,
                clean: (localResult.phishscan_clean || []).length,
                rateLimited: localResult.phishscan_rate_limited === true
              });
            });
          }
        }
        resolve(cachedLanguage);
      });
    });
  }

  // Initial load (fire and forget, but scanPage will await it too)
  loadLanguagePreferences();

  // Get translated text
  function t(key, ...args) {
    const lang = detectLanguage();
    const langTranslations = translations[lang] || translations.en;
    const translation = langTranslations[key];

    if (typeof translation === 'function') {
      return translation(...args);
    }

    // Fallback to English
    const fallback = translations.en[key];
    if (typeof fallback === 'function') {
      return fallback(...args);
    }
    return translation || fallback;
  }

  // In-page status banner to show overall result without needing the popup
  let statusBannerEl = null;

  function ensureStatusBanner() {
    // Skip banner injection on Gmail to avoid cluttering the interface (we have a specialized dashboard there)
    if (window.location.hostname === 'mail.google.com') {
      return document.createElement('div'); // Return dummy element to preventing errors
    }

    if (statusBannerEl) return statusBannerEl;
    statusBannerEl = document.createElement('div');
    statusBannerEl.id = 'phishscan-status-banner';
    const lang = detectLanguage();
    const fontFamily = lang === 'hi' || lang === 'gu'
      ? '"Noto Sans Devanagari", "Noto Sans Gujarati", system-ui, sans-serif'
      : 'system-ui, -apple-system, sans-serif';

    statusBannerEl.style.cssText = `
      position: fixed;
      top: 12px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 2147483647;
      padding: 10px 14px;
      border-radius: 10px;
      background: #1f2937;
      color: #e5e7eb;
      font-family: ${fontFamily};
      font-size: 13px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: default;
      opacity: 0.95;
    `;
    document.body.appendChild(statusBannerEl);
    return statusBannerEl;
  }

  function updatePageStatusBanner({ totalScanned, threats, clean, rateLimited }) {
    const el = ensureStatusBanner();
    let text = '';
    let bg = '#1f2937';
    let border = '#4b5563';

    if (rateLimited) {
      text = t('rateLimited');
      bg = '#78350f';
      border = '#f59e0b';
    } else if (threats > 0) {
      text = t('threatsDetected', threats);
      bg = '#7f1d1d';
      border = '#ef4444';
    } else if (totalScanned === 0) {
      text = t('noLinksFound');
      bg = '#1f2937';
      border = '#4b5563';
    } else {
      text = t('pageSafe', totalScanned);
      bg = '#064e3b';
      border = '#34d399';
    }

    el.textContent = text;
    el.style.background = bg;
    el.style.border = `1px solid ${border}`;
  }

  // Initialize scanning
  function initializeScanning() {
    // Clear previous highlights
    document.querySelectorAll('[data-phishscan]').forEach(el => {
      el.removeAttribute('data-phishscan');
      el.style.border = '';
      el.style.backgroundColor = '';
      const warning = el.querySelector('span');
      if (warning) warning.remove();
    });

    // Clear processed URLs cache
    processedUrls.clear();

    // Reset rate limit flag
    rateLimitReached = false;

    // Start initial scan
    scanPage();

    // Set up DOM observer for dynamic content
    if (observer) {
      observer.disconnect();
    }

    observer = new MutationObserver((mutations) => {
      let shouldScan = false;

      for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.querySelector && (node.querySelector('a[href]') || node.querySelector('form[action]'))) {
                shouldScan = true;
                break;
              }
            }
          }
        }
      }

      if (shouldScan && !rateLimitReached) {
        debouncedScan();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false
    });
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeScanning);
  } else {
    initializeScanning();
  }

  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'FORCE_SCAN') {
      initializeScanning();
      sendResponse({ success: true });
    } else if (request.type === 'LANGUAGE_CHANGED') {
      // Update cached language
      cachedLanguage = request.language;

      // Re-initialize scanning to apply new language to existing elements
      initializeScanning();

      sendResponse({ success: true });
    }
  });

  // Cleanup on page unload
  window.addEventListener('beforeunload', () => {
    if (observer) {
      observer.disconnect();
    }
    processedUrls.clear();
  });
} 