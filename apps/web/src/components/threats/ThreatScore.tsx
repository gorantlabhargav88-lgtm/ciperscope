import type { FC } from 'react';
import { cn } from '../../lib/utils';

function bandFor(score: number): { label: string; cls: string } {
  if (score >= 80) return { label: 'CRITICAL', cls: 'bg-security-critical/10 text-security-critical border-security-critical/20' };
  if (score >= 60) return { label: 'HIGH', cls: 'bg-security-high/10 text-security-high border-security-high/20' };
  if (score >= 30) return { label: 'MEDIUM', cls: 'bg-security-medium/10 text-security-medium border-security-medium/20' };
  return { label: 'LOW', cls: 'bg-security-low/10 text-security-low border-security-low/20' };
}

/** Reflects FusionEngine's real 0-100 additive score and its CRITICAL/HIGH/MEDIUM/LOW thresholds. */
export const ThreatScore: FC<{ score: number; className?: string }> = ({ score, className }) => {
  const { label, cls } = bandFor(score);
  return (
    <div className={cn('flex items-center gap-2 font-semibold px-2 py-1 rounded border w-fit', cls, className)}>
      <span className="text-lg leading-none">{Math.round(score)}</span>
      <span className="text-[10px] opacity-70">/100</span>
      <span className="text-[10px] font-bold tracking-wide ml-1">{label}</span>
    </div>
  );
};
