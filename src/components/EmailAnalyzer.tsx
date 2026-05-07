
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


export default EmailAnalyzer;

