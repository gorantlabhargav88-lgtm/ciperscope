import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Dialog, DialogContent } from '../ui/dialog';
import { apiClient } from '../../lib/apiClient';
import { classifyApiError } from '../../lib/apiErrorState';
import { canSubmitDecision, type DecisionSubmissionState } from '../../features/forensic-timeline/decisionSubmission';
import { getDecisionTarget } from '../../features/forensic-timeline/actionableEvents';
import type { AnalystDecision, AnalystDecisionType, ForensicTimelineEvent, InvestigationSummary } from '@ciperscope/types';

export interface AnalystActionDialogProps {
  event: ForensicTimelineEvent;
  action: AnalystDecisionType;
  caseId: string;
  investigations: InvestigationSummary[];
  onClose: () => void;
  onRecorded: (decision: AnalystDecision, investigationId: string) => void;
}

const ACTION_LABELS: Record<AnalystDecisionType, string> = {
  REVIEWED: 'Review',
  CONFIRMED: 'Confirm Threat',
  ESCALATED: 'Escalate',
  DISMISSED: 'Dismiss',
};

/**
 * Confirmation dialog for recording a real analyst decision against a
 * timeline event, via the existing POST
 * /cases/:caseId/investigations/:investigationId/decisions endpoint
 * (requires CASE_UPDATE — enforced server-side, not here).
 *
 * A decision is recorded per-investigation, but timeline events are
 * case-level, so when a case has more than one investigation the analyst
 * must pick which one this decision belongs to — this is real data
 * (the case's actual investigation list), not a fabricated choice.
 */
export function AnalystActionDialog({ event, action, caseId, investigations, onClose, onRecorded }: AnalystActionDialogProps) {
  const [investigationId, setInvestigationId] = useState(investigations[0]?.id ?? '');
  const [reason, setReason] = useState('');
  const [state, setState] = useState<DecisionSubmissionState>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const target = getDecisionTarget(event);

  const handleSubmit = async () => {
    if (!canSubmitDecision(state)) return;
    if (!investigationId) {
      setState('error');
      setErrorMessage('No investigation exists for this case yet — a decision must be attached to an investigation.');
      return;
    }

    setState('submitting');
    setErrorMessage(null);
    try {
      await apiClient.recordAnalystDecision(caseId, investigationId, {
        targetId: target.targetId,
        targetType: target.targetType,
        decision: action,
        reason: reason.trim() || undefined,
      });
      setState('success');
      onRecorded(
        {
          targetId: target.targetId,
          targetType: target.targetType,
          decision: action,
          reason: reason.trim() || undefined,
          createdAt: new Date().toISOString(),
        },
        investigationId
      );
      onClose();
    } catch (err) {
      const classified = classifyApiError(err, 'analyst decision');
      setState('error');
      setErrorMessage(classified.message);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="p-6 space-y-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">{ACTION_LABELS[action]}</h2>
          <p className="text-xs text-slate-500 mt-1">Recording a real analyst decision — this cannot be undone from this dialog.</p>
        </div>

        <div className="bg-slate-950 border border-slate-800 rounded p-3 text-xs space-y-1">
          <div className="flex justify-between"><span className="text-slate-500">Event</span><span className="text-slate-200 text-right max-w-[280px]">{event.title}</span></div>
          <div className="flex justify-between"><span className="text-slate-500">Category</span><span className="text-slate-300">{event.category}</span></div>
          {event.emailId && <div className="flex justify-between"><span className="text-slate-500">Email</span><span className="text-slate-300 font-mono">{event.emailId}</span></div>}
          {event.evidenceId && <div className="flex justify-between"><span className="text-slate-500">Evidence</span><span className="text-slate-300 font-mono">{event.evidenceId}</span></div>}
          <div className="flex justify-between"><span className="text-slate-500">Action</span><span className="text-slate-200 font-semibold">{ACTION_LABELS[action]}</span></div>
        </div>

        {investigations.length === 0 ? (
          <div className="text-xs text-amber-400 bg-amber-950/20 border border-amber-900/40 rounded p-3">
            No investigation exists for this case yet. Open an investigation before recording an analyst decision.
          </div>
        ) : investigations.length > 1 ? (
          <div>
            <label className="text-xs text-slate-400 block mb-1">Investigation</label>
            <select
              value={investigationId}
              onChange={(e) => setInvestigationId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-200"
            >
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>{inv.title}</option>
              ))}
            </select>
          </div>
        ) : null}

        <div>
          <label className="text-xs text-slate-400 block mb-1">Note (optional)</label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-200 resize-none"
            placeholder="Add context for this decision…"
          />
        </div>

        {errorMessage && <div className="text-xs text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-2">{errorMessage}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="text-xs px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!canSubmitDecision(state) || investigations.length === 0}
            className="text-xs px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
          >
            {state === 'submitting' && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            {state === 'submitting' ? 'Recording…' : `Confirm ${ACTION_LABELS[action]}`}
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
