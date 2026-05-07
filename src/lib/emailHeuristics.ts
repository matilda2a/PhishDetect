export interface EmailFinding {
  severity: 'low' | 'medium' | 'high';
  category: string;
  message: string;
  points: number;
}

export interface EmailAnalysisResult {
  score: number;
  threatLevel: 'Low' | 'Medium' | 'High';
  findings: EmailFinding[];
  messages: string[];
}

const URGENCY_KEYWORDS: string[] = [
  'suspended', 'urgent', 'action required', 'immediately', 'within 24 hours',
  '48 hours', 'final notice', 'will be terminated', 'account locked',
  'unauthorized access', 'security alert', 'security breach', 'expired',
  'reactivate', 'failure to respond', 'limited time', 'act now',
  'your account will be', 'verify now',
];

const THREAT_PHRASES: string[] = [
  'legal action', 'law enforcement', 'arrest', 'criminal', 'lawsuit',
  'penalty', 'prosecuted', 'fine', 'overdue',
];

const GENERIC_GREETINGS: string[] = [
  'dear customer', 'dear user', 'valued client', 'dear member',
  'dear account holder', 'attention user', 'hello customer', 'dear sir',
  'dear madam', 'dear sir/madam', 'to whom it may concern',
];

const PRIZE_OFFERS: string[] = [
  'you have won', 'you are selected', 'lucky winner', 'million dollar',
  'lottery', 'prize money', 'unclaimed reward', 'gift card', 'free iphone',
  'claim your reward', 'claim now', 'inheritance', 'wire transfer',
  'nigerian prince', 'business proposal',
];

const SENSITIVE_REQUESTS: string[] = [
  'enter your password', 'confirm your password', 'verify your credit card',
  'provide your ssn', 'social security', 'credit card number', 'card details',
  'billing information', 'bank account', 'login credentials', 'update payment',
  'verify your account', 'confirm your identity',
];

const SUSPICIOUS_LINK_PATTERNS: RegExp[] = [
  /click here/i, /click the link below/i, /follow this link/i,
  /http:\/\//i,
  /bit\.ly/i, /tinyurl/i, /goo\.gl/i,
];

const IMPERSONATION_BRANDS: string[] = [
  'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'irs', 'hmrc', 'bank of america', 'chase',
  'wells fargo', 'citibank', 'usps', 'fedex', 'dhl', 'linkedin',
];

function detectPoorGrammar(text: string): boolean {
  const doubleSpace  = /  +/.test(text);
  const randomCaps   = (text.match(/\b[a-z]+[A-Z][a-z]+\b/g) || []).length > 2;
  const ellipsis     = (text.match(/\.{4,}/g) || []).length > 0;
  const noSpaceComma = /,[^\s]/.test(text);
  return [doubleSpace, randomCaps, ellipsis, noSpaceComma].filter(Boolean).length >= 2;
}

export function analyzeEmailContent(content: string): EmailAnalysisResult {
  const text     = content.toLowerCase();
  const findings: EmailFinding[] = [];

  function add(severity: EmailFinding['severity'], category: string, message: string, points: number) {
    findings.push({ severity, category, message, points });
  }

  const urgencyHits = URGENCY_KEYWORDS.filter(kw => text.includes(kw));
  if (urgencyHits.length > 0) {
    add('high', 'Urgency Tactics', `Urgency detected: "${urgencyHits.slice(0, 3).join('", "')}"`, Math.min(urgencyHits.length * 12, 40));
  }

  const threatHits = THREAT_PHRASES.filter(kw => text.includes(kw));
  if (threatHits.length > 0) {
    add('high', 'Threat Language', `Intimidation detected: "${threatHits.slice(0, 2).join('", "')}"`, 35);
  }

  const greetingHit = GENERIC_GREETINGS.find(kw => text.includes(kw));
  if (greetingHit) {
    add('medium', 'Generic Greeting', `Non-personalized greeting: "${greetingHit}"`, 20);
  }

  const prizeHits = PRIZE_OFFERS.filter(kw => text.includes(kw));
  if (prizeHits.length > 0) {
    add('high', 'Suspicious Offers', `Prize keywords found: "${prizeHits.slice(0, 3).join('", "')}"`, Math.min(prizeHits.length * 18, 50));
  }

  const sensitiveHits = SENSITIVE_REQUESTS.filter(kw => text.includes(kw));
  if (sensitiveHits.length > 0) {
    add('high', 'Credential Harvesting', `Request for sensitive data: "${sensitiveHits.slice(0, 2).join('", ')}"`, 40);
  }

  const linkHits = SUSPICIOUS_LINK_PATTERNS.filter(rx => rx.test(content));
  if (linkHits.length > 0) {
    add('medium', 'Suspicious Links', `${linkHits.length} suspicious link patterns found.`, linkHits.length * 10);
  }

  const brandHits = IMPERSONATION_BRANDS.filter(b => text.includes(b));
  if (brandHits.length > 0 && (urgencyHits.length > 0 || sensitiveHits.length > 0)) {
    add('high', 'Brand Impersonation', `Mentions brand(s) "${brandHits.slice(0, 2).join('", ')}" with urgency.`, 35);
  }

  if (detectPoorGrammar(content)) {
    add('low', 'Formatting', 'Unusual formatting detected.', 10);
  }

  if (content.length < 250 && urgencyHits.length > 0) {
    add('medium', 'Short + Urgent', 'Short urgent message.', 15);
  }

  const rawScore = findings.reduce((acc, f) => acc + f.points, 0);
  const score    = Math.min(rawScore, 100);

  let threatLevel: 'Low' | 'Medium' | 'High' = 'Low';
  if      (score >= 70) threatLevel = 'High';
  else if (score >= 35) threatLevel = 'Medium';

  return {
    score,
    threatLevel,
    findings,
    messages: findings.length > 0 ? findings.map(f => f.message) : ['Clean.'],
  };
}

