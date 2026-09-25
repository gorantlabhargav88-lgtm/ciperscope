import { useState, Fragment } from 'react';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Loader2, AlertTriangle, ShieldOff, ShieldCheck, Search, ChevronDown, ChevronRight } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';

// Maps AuditLog.resource (services/api/src/utils/audit.ts) to a real
// frontend route this app has today — only resources with a genuine
// detail/list route get a link; everything else renders as plain text.
function resourceLink(resource: string, resourceId: string | null): string | null {
  if (!resourceId) return null;
  switch (resource) {
    case 'Case':
      return `/cases/${resourceId}`;
    case 'Email':
      return `/email-analysis/${resourceId}`;
    case 'Evidence':
      return `/evidence/${resourceId}`;
    default:
      return null;
  }
}

const STATUS_STYLES: Record<string, string> = {
  SUCCESS: 'bg-security-low/10 text-security-low border-security-low/20',
  FAILURE: 'bg-security-critical/10 text-security-critical border-security-critical/20',
  DENIED: 'bg-security-high/10 text-security-high border-security-high/20',
};

/**
 * Organization-wide Audit Log — GET /audit-log. Same AuditLog table as a
 * case's Change History (CaseDetail.tsx), without the per-case narrowing.
 * AUDIT_LOG_READ-gated; a real 403 is shown (never bypassed) when the
 * current user lacks it.
 */
export const AuditLog = () => {
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null]);
  const [cursorIndex, setCursorIndex] = useState(0);
  const [action, setAction] = useState('');
  const [resource, setResource] = useState('');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const cursor = cursorStack[cursorIndex] ?? undefined;

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['audit-log', cursor, action, resource, search],
    queryFn: () =>
      apiClient.getAuditLog({
        cursor: cursor ?? undefined,
        action: action || undefined,
        resource: resource || undefined,
        q: search || undefined,
      }),
    placeholderData: keepPreviousData,
  });

  const classified = error ? classifyApiError(error, 'audit log') : null;
  const items = data?.items ?? [];

  const resetPaging = () => {
    setCursorStack([null]);
    setCursorIndex(0);
  };

  const goNext = () => {
    if (!data?.nextCursor) return;
    const next = [...cursorStack.slice(0, cursorIndex + 1), data.nextCursor];
    setCursorStack(next);
    setCursorIndex(next.length - 1);
  };

  const goPrev = () => {
    if (cursorIndex === 0) return;
    setCursorIndex(cursorIndex - 1);
  };

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-2 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Audit Log</h1>
        </div>
        <p className="text-slate-400 mt-2">Every recorded action across your organization — authentication, case changes, evidence access, and system events.</p>
      </header>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); resetPaging(); }}
            placeholder="Search action, resource, or resource ID..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-600"
          />
        </div>
        <input
          type="text"
          value={action}
          onChange={(e) => { setAction(e.target.value); resetPaging(); }}
          placeholder="Action (e.g. CASE_UPDATED)"
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:border-blue-600 w-56"
        />
        <input
          type="text"
          value={resource}
          onChange={(e) => { setResource(e.target.value); resetPaging(); }}
          placeholder="Resource (e.g. Case)"
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder:text-slate-500 focus:outline-none focus:border-blue-600 w-44"
        />
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load audit log'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : items.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          No audit events match these filters.
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-4 py-4 font-medium w-6" />
                  <th className="px-4 py-4 font-medium">Timestamp</th>
                  <th className="px-4 py-4 font-medium">Actor</th>
                  <th className="px-4 py-4 font-medium">Action</th>
                  <th className="px-4 py-4 font-medium">Resource</th>
                  <th className="px-4 py-4 font-medium">Resource ID</th>
                  <th className="px-4 py-4 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {items.map((entry) => {
                  const isOpen = expanded === entry.id;
                  const link = resourceLink(entry.resource, entry.resourceId);
                  return (
                    <Fragment key={entry.id}>
                      <tr className="hover:bg-slate-800/30 transition-colors cursor-pointer" onClick={() => setExpanded(isOpen ? null : entry.id)}>
                        <td className="px-4 py-3 text-slate-500">
                          {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </td>
                        <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{new Date(entry.createdAt).toLocaleString()}</td>
                        <td className="px-4 py-3 text-slate-300">
                          {entry.actor ? `${entry.actor.firstName ?? ''} ${entry.actor.lastName ?? ''}`.trim() || entry.actor.email : entry.actorId ? 'Former member' : 'System'}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-xs font-medium border bg-slate-800 text-slate-300 border-slate-700">{entry.action}</span>
                        </td>
                        <td className="px-4 py-3 text-slate-400">{entry.resource}</td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-400 max-w-[160px] truncate" title={entry.resourceId ?? undefined}>
                          {link ? (
                            <Link to={link} className="text-blue-400 hover:text-blue-300" onClick={(e) => e.stopPropagation()}>
                              {entry.resourceId}
                            </Link>
                          ) : (
                            entry.resourceId ?? '—'
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium border ${STATUS_STYLES[entry.status] ?? STATUS_STYLES.SUCCESS}`}>{entry.status}</span>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-950/40">
                          <td />
                          <td colSpan={6} className="px-4 py-4">
                            <div className="text-xs">
                              <div className="text-slate-500 uppercase mb-1">Metadata</div>
                              {entry.metadata && Object.keys(entry.metadata).length > 0 ? (
                                <pre className="font-mono text-slate-300 whitespace-pre-wrap break-all bg-slate-900 border border-slate-800 rounded p-3">
                                  {JSON.stringify(entry.metadata, null, 2)}
                                </pre>
                              ) : (
                                <span className="text-slate-600">No additional metadata.</span>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 text-xs text-slate-400">
            <span>
              {items.length} event{items.length !== 1 ? 's' : ''} on this page
              {isFetching && <Loader2 className="inline w-3 h-3 ml-2 animate-spin" />}
            </span>
            <div className="flex gap-2">
              <button
                onClick={goPrev}
                disabled={cursorIndex === 0}
                className="px-3 py-1.5 rounded border border-slate-800 bg-slate-950 disabled:opacity-40 hover:border-blue-600 transition-colors"
              >
                Previous
              </button>
              <button
                onClick={goNext}
                disabled={!data?.nextCursor}
                className="px-3 py-1.5 rounded border border-slate-800 bg-slate-950 disabled:opacity-40 hover:border-blue-600 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
