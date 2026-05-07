import axios, { AxiosError } from 'axios';

const VT_API_KEY  = import.meta.env.VITE_VIRUSTOTAL_API_KEY as string | undefined;
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

export interface VTStats {
  malicious:  number;
  suspicious: number;
  harmless:   number;
  undetected: number;
  timeout?:   number;
}

export interface VTAnalysisResult {
  stats:      VTStats;
  reputation: number;
  totalEngines: number;
  safetyScore: number;
  categories:  string[];
  scan_id:    string;
  permalink?: string;
}

function b64url(s: string): string {
  const base64 = btoa(s);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function pollAnalysis(analysisId: string, headers: Record<string, string>): Promise<VTAnalysisResult> {
  const MAX_ATTEMPTS = 6;
  let delay = 3000;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await sleep(delay);
    const res = await axios.get(`${VT_BASE_URL}/analyses/${analysisId}`, { headers });
    const { status, stats, reputation } = res.data.data.attributes as {
      status: string;
      stats:  VTStats;
      reputation: number;
    };

    if (status === 'completed') {
      return buildResult(stats, reputation, analysisId, undefined);
    }
    delay = Math.min(delay * 1.5, 8000);
  }

  const res = await axios.get(`${VT_BASE_URL}/analyses/${analysisId}`, { headers });
  const { stats, reputation } = res.data.data.attributes as { stats: VTStats; reputation: number };
  return buildResult(stats, reputation, analysisId, undefined);
}

function buildResult(
  stats: VTStats,
  reputation: number,
  scan_id: string,
  permalink?: string,
  categories: string[] = [],
): VTAnalysisResult {
  const total   = (stats.malicious ?? 0) + (stats.suspicious ?? 0) + (stats.harmless ?? 0) + (stats.undetected ?? 0);
  const badVotes = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
  const safetyScore = total > 0 ? Math.round(((total - badVotes) / total) * 100) : 100;

  return { stats, reputation, totalEngines: total, safetyScore, categories, scan_id, permalink };
}

export async function scanURLWithVirusTotal(url: string): Promise<VTAnalysisResult | null> {
  if (!VT_API_KEY) {
    return getMockVTData(url);
  }

  const headers = { 'x-apikey': VT_API_KEY };

  try {
    const encoded = b64url(url);
    try {
      const reportRes = await axios.get(`${VT_BASE_URL}/urls/${encoded}`, { headers });
      const attr = reportRes.data.data.attributes;
      const cats = attr.categories ? Object.values(attr.categories as Record<string, string>) : [];
      return buildResult(attr.last_analysis_stats, attr.reputation ?? 0, reportRes.data.data.id, attr.permalink, cats as string[]);
    } catch (lookupErr) {
      if ((lookupErr as AxiosError)?.response?.status !== 404) throw lookupErr;
    }

    const submitRes = await axios.post(
      `${VT_BASE_URL}/urls`,
      new URLSearchParams({ url }),
      { headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' } },
    );
    const analysisId: string = submitRes.data.data.id;
    return await pollAnalysis(analysisId, headers);

  } catch (err) {
    throw new Error('VirusTotal scan failed.');
  }
}

function getMockVTData(url: string): VTAnalysisResult {
  const lower = url.toLowerCase();
  const isHighRisk = lower.includes('paypa1') || lower.includes('login-verify')
    || lower.includes('secure-') || lower.includes('account-confirm');
  const isMedRisk  = lower.startsWith('http://') || lower.includes('bit.ly');

  const stats: VTStats = isHighRisk
    ? { malicious: 14, suspicious: 6, harmless: 42, undetected: 8 }
    : isMedRisk
    ? { malicious: 3,  suspicious: 4, harmless: 65, undetected: 10 }
    : { malicious: 0,  suspicious: 1, harmless: 78, undetected:  8 };

  const reputation = isHighRisk ? -22 : isMedRisk ? -4 : 52;
  const cats = isHighRisk ? ['phishing', 'malware'] : isMedRisk ? ['suspicious'] : ['trusted'];

  return buildResult(stats, reputation, 'mock_scan_' + Date.now(), undefined, cats);
}

