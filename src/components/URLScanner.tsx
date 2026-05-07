import {
  AlertTriangle, CheckCircle,
  ShieldOff
} from 'lucide-react';
import React from 'react';
import { type HeuristicResult } from '../lib/urlHeuristics';
import { type VTAnalysisResult } from '../services/virusTotal';

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



export default URLScanner;

