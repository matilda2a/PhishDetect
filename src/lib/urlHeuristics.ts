export interface HeuristicFlag {
  severity: 'low' | 'medium' | 'high';
  message: string;
  points: number;
}

export interface HeuristicResult {
  passed: boolean;
  score: number;
  flags: HeuristicFlag[];
  details: string[];
}

const POPULAR_DOMAINS: string[] = [
  'paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'facebook.com',
  'amazon.com', 'netflix.com', 'instagram.com', 'twitter.com', 'linkedin.com',
  'github.com', 'dropbox.com', 'adobe.com', 'spotify.com', 'bankofamerica.com',
  'chase.com', 'wellsfargo.com', 'citibank.com', 'ebay.com', 'yahoo.com',
  'outlook.com', 'live.com', 'office.com', 'icloud.com', 'dhl.com', 'fedex.com',
  'ups.com', 'usps.com', 'irs.gov', 'gov.uk',
];

const URL_SHORTENERS: string[] = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'buff.ly', 'rb.gy',
  'short.link', 'tiny.cc', 'is.gd', 'clck.ru', 'cutt.ly', 'shorturl.at',
];

const SUSPICIOUS_TLDS: string[] = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.work',
  '.loan', '.date', '.bid', '.win', '.download', '.racing', '.stream',
  '.gdn', '.review', '.country', '.kim', '.men', '.party',
];

const SUSPICIOUS_PATH_KEYWORDS: string[] = [
  'login', 'signin', 'verify', 'secure', 'account', 'update',
  'confirm', 'banking', 'wallet', 'password', 'credential', 'auth',
  'alert', 'safety', 'support', 'billing', 'service'
];

const HOMOGRAPH_MAP: Record<string, string> = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a',
};

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function normalizeHomographs(s: string): string {
  return s.split('').map(c => HOMOGRAPH_MAP[c] ?? c).join('');
}

function getRegistrableDomain(hostname: string): string {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

export function analyzeURLHeuristics(urlStr: string): HeuristicResult {
  const flags: HeuristicFlag[] = [];
  let score = 100;

  function applyPenalty(severity: HeuristicFlag['severity'], message: string, penalty: number) {
    flags.push({ severity, message, points: penalty });
    score -= penalty;
  }

  const hasExplicitScheme = /^https?:\/\//i.test(urlStr);

  let url: URL;
  try {
    const withScheme = hasExplicitScheme ? urlStr : `https://${urlStr}`;
    url = new URL(withScheme);
  } catch {
    return {
      passed: false,
      score: 0,
      flags: [{ severity: 'high', message: 'Invalid URL format.', points: 100 }],
      details: ['Invalid URL format.'],
    };
  }

  const hostname  = url.hostname.toLowerCase();
  const fullURL   = url.toString().toLowerCase();
  const regDomain = getRegistrableDomain(hostname);
  
  let isTrustedBrand = false;
  let brandImpersonationDetected = false;

  for (const domain of POPULAR_DOMAINS) {
    if (hostname === domain || hostname.endsWith('.' + domain)) {
      isTrustedBrand = true;
      break;
    }
  }

  if (hasExplicitScheme && url.protocol === 'http:') {
    applyPenalty('high', 'Insecure protocol (HTTP) detected.', 30);
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    applyPenalty('high', 'IP address used instead of domain.', 50);
  }

  if (url.port && !['80', '443'].includes(url.port)) {
    applyPenalty('medium', `Non-standard port detected: :${url.port}`, 20);
  }

  if (url.username || url.password) {
    applyPenalty('high', 'User credentials detected in URL.', 50);
  }

  if (URL_SHORTENERS.includes(regDomain)) {
    applyPenalty('medium', `URL shortener detected (${regDomain})`, 30);
  }

  const tldMatch = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  if (tldMatch) {
    applyPenalty('medium', `Suspicious TLD "${tldMatch}" detected.`, 20);
  }

  const subdomainDepth = hostname.split('.').length - 2;
  if (subdomainDepth > 3) {
    applyPenalty('low', `Excessive subdomain nesting (${subdomainDepth} levels).`, 15);
  }

  if (!isTrustedBrand) {
    for (const domain of POPULAR_DOMAINS) {
      const brand = domain.split('.')[0];
      const normalized = normalizeHomographs(hostname);
      if (normalized !== hostname && (normalized.includes(brand) || levenshtein(normalized, domain) <= 1)) {
        applyPenalty('high', `Character substitution mimicking "${brand}"`, 60);
        brandImpersonationDetected = true;
        break;
      }
      const dist = levenshtein(regDomain, domain);
      if (dist > 0 && dist <= 2) {
        applyPenalty('high', `Typosquatting detected for "${domain}"`, 60);
        brandImpersonationDetected = true;
        break;
      }
      const brandRegex = new RegExp(`(^|[-.])(${brand})([-.]|$)`, 'i');
      if (brandRegex.test(hostname)) {
        applyPenalty('high', `Unauthorized brand name inclusion ("${brand}")`, 60);
        brandImpersonationDetected = true;
        break;
      }
    }
  }

  const allParams = url.pathname + url.search + url.hash;
  const keywordsFound = SUSPICIOUS_PATH_KEYWORDS.filter(k => allParams.toLowerCase().includes(k));
  if (keywordsFound.length > 0) {
    applyPenalty(keywordsFound.length >= 2 ? 'medium' : 'low', `Suspicious keywords found: ${keywordsFound.join(', ')}`, Math.min(keywordsFound.length * 15, 45));
  }

  if (fullURL.length > 100) {
    applyPenalty('medium', 'Extremely long URL.', 15);
  }

  const hyphenCount = (regDomain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    applyPenalty('low', `Excessive hyphens (${hyphenCount}) in domain.`, 10);
  }

  const criticalFlags = flags.filter(f => f.severity === 'high').length;
  const hasIPFlag = flags.some(f => f.message.includes('IP address used'));
  if (criticalFlags >= 2 || (brandImpersonationDetected && hasExplicitScheme && url.protocol === 'http:') || hasIPFlag) {
    score = Math.min(score, 45);
  }

  const finalScore = Math.max(0, Math.min(100, score));

  return {
    passed: finalScore >= 75,
    score: finalScore,
    flags,
    details: flags.length > 0 ? flags.map(f => f.message) : ['Clean.'],
  };
}

