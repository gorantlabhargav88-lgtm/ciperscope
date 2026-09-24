import { useQuery } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { apiClient } from '../../lib/apiClient';
import { classifyApiError } from '../../lib/apiErrorState';
import type { CaseHistoryEntry } from '@ciperscope/types';

const ACTION_LABELS: Record<string, string> = {
  CASE_CREATED: 'Case created',
  CASE_UPDATED: 'Case updated',
  CASE_ASSIGNED: 'Assignment changed',
};

function actorLabel(actor: CaseHistoryEntry['actor']): string {
  if (!actor) return 'System';
  const name = [actor.firstName, actor.lastName].filter(Boolean).join(' ');
  return name || actor.email;
}

function describeEntry(entry: CaseHistoryEntry): string {
  if (entry.action === 'CASE_ASSIGNED') {
    return entry.assignedUser ? `Assigned to ${actorLabel(entry.assignedUser)}` : 'Unassigned';
  }
  return ACTION_LABELS[entry.action] ?? entry.action;
}

/** Case record's own change/audit trail (GET /cases/:caseId/history) — distinct from the broader forensic timeline. */
export function CaseHistory({ caseId }: { caseId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['case-history', caseId],
    queryFn: () => apiClient.getCaseHistory(caseId),
  });

  const classified = error ? classifyApiError(error, "case's history") : null;

  if (isLoading) {
    return <div className="flex justify-center py-6"><Loader2 className="w-5 h-5 text-blue-500 animate-spin" /></div>;
  }
  if (classified) {
    return <p className="text-xs text-red-400">{classified.message}</p>;
  }
  if (!data || data.items.length === 0) {
    return <p className="text-slate-500 italic text-sm">No recorded changes for this case yet.</p>;
  }

  return (
    <div className="space-y-2">
      {data.items.map((entry) => (
        <div key={entry.id} className="bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs flex items-center justify-between gap-3">
          <div>
            <span className="text-slate-200 font-medium">{describeEntry(entry)}</span>
            <span className="text-slate-500 ml-2">by {actorLabel(entry.actor)}</span>
          </div>
          <span className="text-slate-600 shrink-0">{new Date(entry.createdAt).toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}
