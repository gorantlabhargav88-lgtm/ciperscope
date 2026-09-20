import type { ThreatPriority, ThreatPriorityResult, Severity } from '@ciperscope/types';

const PRIORITY_STYLES: Record<ThreatPriority, string> = {
  P1: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  P2: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  P3: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
};

export interface ThreatPriorityExplanationProps {
  priority: ThreatPriorityResult;
  threatScore: number | null;
  severity: Severity | null;
  maliciousIndicatorCount: number;
  authenticationFailed: boolean;
  mlClassification: string | null;
}

const Row = ({ label, value }: { label: string; value: React.ReactNode }) => (
  <div className="flex justify-between items-center text-xs py-1.5 border-b border-slate-800/50 last:border-0">
    <span className="text-slate-500">{label}</span>
    <span className="text-slate-200 font-medium">{value}</span>
  </div>
);

/**
 * Renders the deterministic P1/P2/P3 result from
 * @ciperscope/types calculateThreatPriority() alongside every real signal
 * that fed it. This is CiperScope's own operational prioritization policy,
 * not a scientifically validated risk model — the disclaimer is always shown.
 * Any signal CiperScope did not actually compute is shown as
 * "Not available", never guessed at.
 */
export function ThreatPriorityExplanation({
  priority,
  threatScore,
  severity,
  maliciousIndicatorCount,
  authenticationFailed,
  mlClassification,
}: ThreatPriorityExplanationProps) {
  return (
    <div className={`rounded-lg border p-4 ${PRIORITY_STYLES[priority.priority]}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-lg font-bold">{priority.priority}</span>
        <span className="text-[10px] uppercase tracking-wide opacity-75">Operational priority — not a severity rename</span>
      </div>

      <div className="bg-slate-950/40 rounded p-3 mb-3">
        <Row label="Threat Score" value={threatScore ?? 'Not available'} />
        <Row label="Severity" value={severity ?? 'Not available'} />
        <Row label="Malicious/Suspicious Indicators" value={maliciousIndicatorCount} />
        <Row label="Authentication Failure (SPF/DMARC)" value={authenticationFailed ? 'Yes' : 'No'} />
        <Row label="ML Classification" value={mlClassification ?? 'Not available'} />
      </div>

      <div className="text-xs">
        <div className="font-semibold mb-1">Escalation Reason</div>
        <ul className="list-disc list-inside space-y-0.5 opacity-90">
          {priority.reasons.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      </div>

      <div className="mt-3 pt-2 border-t border-white/10 text-[10px] opacity-60">
        Deterministic CiperScope operational policy — not a scientifically validated prediction. DKIM is deliberately
        excluded from this calculation because it is not cryptographically verified.
      </div>
    </div>
  );
}
