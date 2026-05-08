import {
  Activity,
  AlertTriangle, CheckCircle, ExternalLink,
  Globe,
  Loader2,
  Lock,
  Search, Shield,
  ShieldAlert,
  ShieldOff,
  Unlock, X
} from 'lucide-react';
import React, { useRef, useState } from 'react';
import { analyzeURLHeuristics, type HeuristicResult } from '../lib/urlHeuristics';
import { scanURLWithVirusTotal, type VTAnalysisResult } from '../services/virusTotal';

function getOverallScore(h: HeuristicResult | null, vt: VTAnalysisResult | null): number {
  const hScore = h?.score;
  const vtScore = vt?.safetyScore;
  if (hScore !== undefined && vtScore !== undefined) return Math.round((hScore + vtScore) / 2);
  if (hScore !== undefined) return hScore;
  if (vtScore !== undefined) return vtScore;
  return 100;
}

function getStatusConfig(score: number) {
  if (score < 50) return { label: 'Dangerous', icon: ShieldOff, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', bar: 'bg-red-500' };
  if (score < 75) return { label: 'Suspicious', icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', bar: 'bg-amber-500' };
  return { label: 'Safe', icon: CheckCircle, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', bar: 'bg-emerald-500' };
}



const RadialProgress: React.FC<{ score: number; colorClass: string }> = ({ score, colorClass }) => {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const dash = circ - (score / 100) * circ;
  return (
    <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)' }}>
      <circle cx="70" cy="70" r={r} strokeWidth="10" stroke="rgba(255,255,255,0.06)" fill="none" />
      <circle cx="70" cy="70" r={r} strokeWidth="10" fill="none" stroke="currentColor"
        className={colorClass} strokeDasharray={circ} strokeDashoffset={dash}
        strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1s ease' }} />
    </svg>
  );
};



const URLScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState<string | null>(null);
  const [hResult, setHResult] = useState<HeuristicResult | null>(null);
  const [vtResult, setVtResult] = useState<VTAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setIsScanning(true);
    setError(null);
    setHResult(null);
    setVtResult(null);
    try {
      setScanStage('Analyzing heuristics...');
      const h = analyzeURLHeuristics(url.trim());
      setHResult(h);
      setScanStage('Checking VirusTotal...');
      const vt = await scanURLWithVirusTotal(url.trim());
      setVtResult(vt);
    } catch (err) {
      setError((err as Error).message || 'Scan failed.');
    } finally {
      setIsScanning(false);
      setScanStage(null);
    }
  };

  const clearResults = () => { setUrl(''); setHResult(null); setVtResult(null); setError(null); inputRef.current?.focus(); };

  const overall = getOverallScore(hResult, vtResult);
  const cfg = getStatusConfig(overall);
  const hasResults = hResult !== null;
  const isHTTPS = url.toLowerCase().startsWith('https');

  return (
    <div className="space-y-8">
      <div className="glass rounded-3xl p-8 md:p-10 space-y-6">
        <div className="text-center space-y-2">
          <h2 className="text-3xl font-extrabold tracking-tight">URL Scanner</h2>
          <p className="text-muted-foreground text-sm">Analyze links for phishing patterns and community threats.</p>
        </div>

        <form onSubmit={handleScan} className="max-w-3xl mx-auto">
          <div className="relative group">
            <div className="absolute inset-y-0 left-5 flex items-center pointer-events-none text-muted-foreground group-focus-within:text-primary transition-colors">
              <Globe size={20} />
            </div>
            <input ref={inputRef} type="text"
              placeholder="Enter URL to analyze..."
              value={url} onChange={e => setUrl(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-2xl py-5 pl-14 pr-36 focus:ring-2 focus:ring-primary/50 focus:border-primary outline-none transition-all text-base" />
            {url && (
              <button type="button" onClick={() => setUrl('')}
                className="absolute right-36 inset-y-0 px-3 text-muted-foreground hover:text-white transition-colors">
                <X size={16} />
              </button>
            )}
            <button type="submit" disabled={isScanning || !url.trim()}
              className="absolute right-3 inset-y-3 px-6 bg-primary text-white rounded-xl font-bold hover:bg-primary/80 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 text-sm">
              {isScanning ? <><Loader2 className="animate-spin" size={16} />Scanning</> : 'Scan'}
            </button>
          </div>
        </form>

        {isScanning && scanStage && (
          <div className="max-w-3xl mx-auto flex items-center gap-3 p-4 rounded-xl bg-primary/10 border border-primary/20 text-sm text-primary">
            <Loader2 className="animate-spin shrink-0" size={16} />{scanStage}
          </div>
        )}
      </div>

      {hasResults && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            <div className={`glass rounded-3xl p-6 flex flex-col items-center justify-center text-center space-y-3 border-2 ${cfg.border} ${cfg.bg}`}>
              <div className="relative">
                <RadialProgress score={overall} colorClass={cfg.color} />
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className={`text-3xl font-black ${cfg.color}`}>{overall}</span>
                  <span className="text-xs text-muted-foreground">/100</span>
                </div>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-widest font-medium">Safety Score</p>
                <p className={`text-2xl font-black ${cfg.color}`}>{cfg.label}</p>
              </div>
              <button onClick={clearResults} className="text-xs text-muted-foreground hover:text-white underline underline-offset-2">Reset</button>
            </div>

            <div className="glass rounded-3xl p-6 flex flex-col items-center justify-center text-center space-y-2 hover:scale-[1.02] transition-transform">
              {isHTTPS ? <Lock size={36} className="text-emerald-400" /> : <Unlock size={36} className="text-red-400" />}
              <p className={`text-sm font-bold ${isHTTPS ? 'text-emerald-400' : 'text-red-400'}`}>{isHTTPS ? 'HTTPS' : 'HTTP'}</p>
              <p className="text-xs text-muted-foreground">{isHTTPS ? 'Encrypted' : 'Unencrypted'}</p>
            </div>

            <div className="glass rounded-3xl p-6 flex flex-col items-center justify-center text-center space-y-2 hover:scale-[1.02] transition-transform">
              <Activity size={36} className="text-primary" />
              <p className="text-3xl font-black">{hResult?.score ?? 0}<span className="text-base font-normal text-muted-foreground">/100</span></p>
              <p className="text-xs text-muted-foreground">Heuristic Score</p>
            </div>

            <div className="glass rounded-3xl p-6 flex flex-col items-center justify-center text-center space-y-2 hover:scale-[1.02] transition-transform">
              <Shield size={36} className="text-primary" />
              <p className="text-3xl font-black">{vtResult?.safetyScore ?? '—'}{vtResult ? '%' : ''}</p>
              <p className="text-xs text-muted-foreground">VT Reputation</p>
            </div>
          </div>

          <div className="glass rounded-3xl p-6 md:p-8 space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary/20 rounded-xl text-primary"><Activity size={20} /></div>
                <h3 className="text-lg font-bold">Comprehensive Analysis</h3>
              </div>
              <span className="text-[10px] uppercase font-black tracking-widest text-muted-foreground bg-white/5 px-3 py-1 rounded-full border border-white/10">
                10 Points Checked
              </span>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              {[
                { id: 'proto', label: 'Protocol', icon: <Lock size={20} />, check: 'Insecure protocol' },
                { id: 'ip',    label: 'IP Routing', icon: <Globe size={20} />, check: 'IP address used' },
                { id: 'spoof', label: 'Spoofing', icon: <ShieldAlert size={20} />, check: /(substitution|typosquatting|unauthorized brand)/i },
                { id: 'tld',   label: 'TLD Check', icon: <Globe size={20} />, check: 'Suspicious TLD' },
                { id: 'sub',   label: 'Subdomains', icon: <Activity size={20} />, check: 'subdomain nesting' },
                { id: 'hyp',   label: 'Hyphens', icon: <Activity size={20} />, check: 'Excessive hyphens' },
                { id: 'key',   label: 'Keywords', icon: <Search size={20} />, check: 'Suspicious keywords' },
                { id: 'short', label: 'Shortener', icon: <ExternalLink size={20} />, check: 'shortener detected' },
                { id: 'cred',  label: 'Credentials', icon: <ShieldOff size={20} />, check: 'User credentials' },
                { id: 'len',   label: 'URL Length', icon: <Activity size={20} />, check: 'long URL' },
              ].map(item => {
                const flag = hResult.flags.find(f => 
                  typeof item.check === 'string' 
                    ? f.message.includes(item.check) 
                    : item.check.test(f.message)
                );
                const isMalicious = !!flag;
                
                return (
                  <div key={item.id} 
                    className={`group relative p-5 rounded-2xl border transition-all duration-300 hover:scale-[1.03] hover:shadow-2xl ${
                      isMalicious 
                        ? 'bg-red-500/5 border-red-500/30 hover:border-red-500 hover:shadow-red-500/10' 
                        : 'bg-white/5 border-white/10 hover:border-primary/50 hover:shadow-primary/10'
                    }`}>
                    <div className="flex flex-col gap-4 h-full">
                      <div className={`p-2.5 w-fit rounded-xl transition-colors ${
                        isMalicious ? 'bg-red-500/20 text-red-400' : 'bg-white/10 text-muted-foreground group-hover:text-primary group-hover:bg-primary/20'
                      }`}>
                        {item.icon}
                      </div>
                      <div className="space-y-1">
                        <p className={`text-xs font-black uppercase tracking-wider ${isMalicious ? 'text-red-400' : 'text-muted-foreground'}`}>
                          {item.label}
                        </p>
                        <p className={`text-[10px] leading-relaxed transition-opacity ${isMalicious ? 'text-red-300/60' : 'text-muted-foreground/30'}`}>
                          {isMalicious ? flag.message : 'No suspicious patterns found.'}
                        </p>
                      </div>
                      <div className={`absolute top-4 right-4 text-[9px] font-black uppercase px-2 py-0.5 rounded-md border ${
                        isMalicious ? 'border-red-500/40 text-red-400 bg-red-500/10' : 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10'
                      }`}>
                        {isMalicious ? 'Failed' : 'Safe'}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="glass rounded-3xl p-6 md:p-8 space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary/20 rounded-xl text-primary"><Shield size={20} /></div>
                <h3 className="text-lg font-bold">Threat Intelligence</h3>
              </div>
              {vtResult?.permalink && (
                <a href={vtResult.permalink} target="_blank" rel="noreferrer"
                  className="text-xs text-primary hover:underline flex items-center gap-1">
                  View Full Report <ExternalLink size={12} />
                </a>
              )}
            </div>

            {vtResult ? (
              <div className="space-y-5">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    { label: 'Malicious',  val: vtResult.stats.malicious,  c: 'red' },
                    { label: 'Suspicious', val: vtResult.stats.suspicious, c: 'amber' },
                    { label: 'Harmless',   val: vtResult.stats.harmless,   c: 'emerald' },
                    { label: 'Undetected', val: vtResult.stats.undetected, c: 'blue' },
                  ].map(({ label, val, c }) => (
                    <div key={label} className={`p-4 rounded-2xl bg-${c}-500/10 border border-${c}-500/20 text-center`}>
                      <p className={`text-3xl font-black text-${c}-400`}>{val}</p>
                      <p className={`text-[10px] uppercase font-bold text-${c}-400/70`}>{label}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-8 border-2 border-dashed border-white/5 rounded-2xl text-center text-muted-foreground italic text-sm">Community data unavailable.</div>
            )}
          </div>
        </div>
      )}

      {!hasResults && !isScanning && !error && (
        <div className="glass rounded-3xl p-12 flex flex-col items-center text-center space-y-6 border-2 border-dashed border-white/5 opacity-70">
          <Search size={52} className="text-muted-foreground" />
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-muted-foreground">Ready for Analysis</h3>
            <p className="text-sm text-muted-foreground/70 max-w-sm mx-auto">
              Enter a URL above or use one of the quick scenarios below to see the detection engine in action.
            </p>
          </div>

          <div className="flex flex-wrap justify-center gap-2 max-w-2xl">
            {[
              { label: 'Clean Site',  url: 'google.com', safe: true },
              { label: 'Homoglyph',   url: 'pаypal.com', risk: true },
              { label: 'Typosquatting', url: 'g00gle.com', risk: true },
              { label: 'Insecure IP', url: 'http://192.168.1.45/login', risk: true },
              { label: 'Shortened',   url: 'bit.ly/secure-auth-xyz', risk: true },
              { label: 'Credential Mask', url: 'https://paypal.com@phish-site.net/verify', risk: true },
              { label: 'Subdomain Padding', url: 'paypal.com-update-security-check.security-verify.net', risk: true },
              { label: 'Suspicious TLD',  url: 'bank-update.xyz', risk: true },
              { label: 'Unusual Port', url: 'http://secure-login.com:8888', risk: true },
              { label: 'Excessive Hyphens', url: 'account-verify-secure-login-update.com', risk: true },
              { label: 'Combo Attack', url: 'http://192.168.1.1/paypa1/login-verify.php?auth=true', risk: true, critical: true },
              { label: 'Bank Mirror', url: 'https://chase-online-secure-auth.xyz/login', risk: true, critical: true },
            ].map(sc => (
              <button key={sc.label} onClick={() => setUrl(sc.url)}
                className={`px-4 py-2 rounded-xl border transition-all text-xs font-medium ${
                  sc.critical 
                    ? 'border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:border-red-500' 
                    : sc.safe
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 hover:border-emerald-500'
                    : 'border-white/10 bg-white/5 text-muted-foreground hover:border-primary/50 hover:text-primary hover:bg-primary/5'
                }`}>
                {sc.label}
              </button>
            ))}

          </div>

        </div>
      )}

    </div>
  );
};

export default URLScanner;

