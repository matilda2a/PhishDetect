
import { AlertCircle, BarChart2, CheckCircle, Mail, Send, ShieldAlert } from 'lucide-react';
import React, { useState } from 'react';
import { analyzeEmailContent, type EmailAnalysisResult, type EmailFinding } from '../lib/emailHeuristics';

function severityBadge(s: 'low' | 'medium' | 'high') {
  return { high: 'bg-red-500/20 text-red-400 border-red-500/30', medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30', low: 'bg-blue-500/20 text-blue-400 border-blue-500/30' }[s];
}

function threatPalette(level: string) {
  switch (level) {
    case 'High': return { text: 'text-red-400', border: 'border-red-500/40', bg: 'bg-red-500/10', bar: 'bg-red-500' };
    case 'Medium': return { text: 'text-amber-400', border: 'border-amber-500/40', bg: 'bg-amber-500/10', bar: 'bg-amber-500' };
    default: return { text: 'text-emerald-400', border: 'border-emerald-500/40', bg: 'bg-emerald-500/10', bar: 'bg-emerald-500' };
  }
}

const CategoryIcon: React.FC<{ cat: string }> = ({ cat }) => {
  const icons: Record<string, React.ReactNode> = {
    'Urgency Tactics': <AlertCircle size={16} />,
    'Threat Language': <ShieldAlert size={16} />,
    'Generic Greeting': <Mail size={16} />,
    'Credential Harvesting': <ShieldAlert size={16} />,
    'Suspicious Links': <AlertCircle size={16} />,
    'Brand Impersonation': <AlertCircle size={16} />,
    'Grammar / Formatting': <BarChart2 size={16} />,
  };
  return <>{icons[cat] ?? <AlertCircle size={16} />}</>;
};

const EmailAnalyzer: React.FC = () => {
  const [content, setContent] = useState('');
  const [result, setResult] = useState<EmailAnalysisResult | null>(null);

  const handleAnalyze = () => {
    if (!content.trim()) return;
    setResult(analyzeEmailContent(content));
  };

  const pal = result ? threatPalette(result.threatLevel) : null;

  return (
    <div className="space-y-8">
      <div className="text-center space-y-2">
        <h2 className="text-3xl font-extrabold tracking-tight">Email Analyzer</h2>
        <p className="text-muted-foreground text-sm">Paste email content to check for common phishing patterns.</p>
      </div>

      <div className="glass rounded-3xl p-6 md:p-8 space-y-5">
        <textarea
          value={content}
          onChange={e => { setContent(e.target.value); setResult(null); }}
          placeholder="Paste email content here..."
          className="w-full bg-white/5 border border-white/10 rounded-2xl p-6 outline-none focus:ring-2 focus:ring-primary/50 transition-all resize-none min-h-[260px] text-sm font-mono leading-relaxed"
        />

        <div className="flex gap-3">
          <button onClick={handleAnalyze} disabled={!content.trim()}
            className="flex-1 py-4 bg-primary text-white rounded-2xl font-bold hover:bg-primary/80 disabled:opacity-40 transition-all flex items-center justify-center gap-2 group">
            Analyze <Send size={16} />
          </button>
          {content && (
            <button onClick={() => { setContent(''); setResult(null); }}
              className="px-6 py-4 border border-white/10 rounded-2xl text-muted-foreground hover:text-white transition-all text-sm font-medium">
              Clear
            </button>
          )}
        </div>
      </div>

      {result && pal && (
        <div className="space-y-6">
          <div className={`glass rounded-3xl p-8 border-2 ${pal.border} ${pal.bg} flex flex-col md:flex-row items-center gap-8`}>
            <div className="text-center shrink-0">
              <p className={`text-7xl font-black ${pal.text}`}>{result.score}</p>
              <p className="text-sm text-muted-foreground mt-1">/ 100</p>
            </div>

            <div className="flex-1 space-y-4 w-full">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-widest font-medium">Threat Level</p>
                  <p className={`text-3xl font-black ${pal.text}`}>{result.threatLevel}</p>
                </div>
                <ShieldAlert size={40} className={pal.text} />
              </div>
              <div className="w-full h-3 bg-white/5 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${pal.bar} transition-all duration-1000`} style={{ width: `${result.score}%` }} />
              </div>
            </div>
          </div>

          {result.findings.length > 0 && (
            <div className="glass rounded-3xl p-6 md:p-8 space-y-5">
              <h3 className="text-lg font-bold">Findings</h3>
              <div className="space-y-3">
                {result.findings.map((f: EmailFinding, i) => (
                  <div key={i} className={`flex items-start gap-4 p-4 rounded-2xl border ${severityBadge(f.severity)}`}>
                    <div className={`p-1.5 rounded-lg border shrink-0 mt-0.5 ${severityBadge(f.severity)}`}>
                      <CategoryIcon cat={f.category} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-xs font-bold uppercase tracking-wider mb-1 ${severityBadge(f.severity).split(' ')[1]}`}>{f.category}</p>
                      <p className="text-sm leading-relaxed">{f.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.findings.length === 0 && (
            <div className="glass rounded-3xl p-8 flex items-center gap-5 border-2 border-emerald-500/30 bg-emerald-500/5">
              <CheckCircle size={40} className="text-emerald-400 shrink-0" />
              <div>
                <h3 className="text-lg font-bold text-emerald-400">No Threats Detected</h3>
                <p className="text-sm text-muted-foreground mt-1">This content doesn't match known phishing patterns.</p>
              </div>
            </div>
          )}
        </div>
      )}

      {!result && !content && (
        <div className="glass rounded-3xl p-12 flex flex-col items-center text-center space-y-6 border-2 border-dashed border-white/5 opacity-60">
          <Mail size={52} className="text-muted-foreground" />
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-muted-foreground">Waiting for Analysis</h3>
            <p className="text-sm text-muted-foreground/70 max-w-sm mx-auto">
              Paste email content above or load one of these common phishing scenarios:
            </p>
          </div>

          <div className="flex flex-wrap justify-center gap-2 max-w-2xl">
            {[
              {
                label: 'Bank Urgency',
                text: 'URGENT: Your account has been suspended! You must verify your credentials within 24 hours at http://bit.ly/bank-auth or your funds will be frozen.'
              },
              {
                label: 'Prize Winner',
                text: 'Congratulations! You have been selected as the lucky winner of a $1000 Amazon gift card. Claim your prize now: http://free-gift-card.xyz'
              },
              {
                label: 'Password Reset',
                text: 'Security Alert: Someone tried to login to your Netflix account from Russia. If this was not you, please reset your password immediately: https://netflix-security-check.com'
              },
            ].map(sample => (
              <button key={sample.label} onClick={() => setContent(sample.text)}
                className="px-4 py-2 rounded-xl border border-white/10 bg-white/5 text-xs text-muted-foreground hover:border-primary/50 hover:text-primary hover:bg-primary/5 transition-all font-medium">
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      )}

    </div>
  );
};

export default EmailAnalyzer;

