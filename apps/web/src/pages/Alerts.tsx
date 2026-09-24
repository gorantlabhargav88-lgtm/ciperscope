import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { Loader2, AlertTriangle, ShieldAlert, ChevronRight, CheckCircle2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { SeverityBadge } from '../components/threats/SeverityBadge';
import type { AlertSeverity } from '../types/severity';

interface AlertItem {
  id: string;
  caseId: string | null;
  title: string;
  message: string;
  severity: AlertSeverity;
  isRead: boolean;
  createdAt: string;
}

export const Alerts = () => {
  const [cursor, setCursor] = useState<string | undefined>();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['alerts', cursor],
    queryFn: () =>
      api.get<{ items: AlertItem[]; nextCursor?: string }>(
        `/alerts?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
      ),
  });

  const markAsRead = async (alertId: string) => {
    try {
      await api.patch(`/alerts/${alertId}`, { isRead: true });
      refetch();
    } catch (e) {
      console.error('Failed to mark alert as read', e);
    }
  };

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-8 h-8 text-red-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Security Alerts</h1>
        </div>
        <p className="text-slate-400 mt-2">Monitor system-wide security notifications and threat intelligence triggers.</p>
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : error ? (
        <div className="bg-red-950/30 border border-red-900/50 p-6 rounded-xl flex items-center gap-4">
          <AlertTriangle className="w-8 h-8 text-red-500" />
          <div>
            <h3 className="text-red-200 font-medium">Failed to load alerts</h3>
            <p className="text-red-400/80 text-sm">{(error as any)?.message}</p>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-6 py-4 font-medium">Severity</th>
                <th className="px-6 py-4 font-medium">Alert message</th>
                <th className="px-6 py-4 font-medium">Generated</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {data?.items?.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-slate-500 italic">
                    No active alerts.
                  </td>
                </tr>
              ) : (
                data?.items?.map((a) => (
                  <tr key={a.id} className={`hover:bg-slate-800/30 transition-colors group ${a.isRead ? 'opacity-60' : ''}`}>
                    <td className="px-6 py-4">
                      <SeverityBadge level={a.severity} />
                    </td>
                    <td className="px-6 py-4">
                      <p className={`font-medium ${a.isRead ? 'text-slate-400' : 'text-slate-200'}`}>{a.title}</p>
                      <p className="text-xs text-slate-500 mt-1 line-clamp-1">{a.message}</p>
                    </td>
                    <td className="px-6 py-4 text-slate-400">{new Date(a.createdAt).toLocaleString()}</td>
                    <td className="px-6 py-4 text-right space-x-3">
                      {!a.isRead && (
                        <button 
                          onClick={() => markAsRead(a.id)}
                          className="text-emerald-400 hover:text-emerald-300 inline-flex items-center text-xs font-medium transition-colors"
                        >
                          <CheckCircle2 className="w-4 h-4 mr-1" /> Mark Read
                        </button>
                      )}
                      {a.caseId && (
                        <Link to={`/cases/${a.caseId}`} className="text-blue-400 hover:text-blue-300 inline-flex items-center text-xs font-medium transition-colors">
                          View Case <ChevronRight className="w-4 h-4 ml-1" />
                        </Link>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          </div>

          {data?.nextCursor && (
            <div className="p-4 border-t border-slate-800 flex justify-center">
              <button 
                onClick={() => setCursor(data.nextCursor)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm font-medium transition-colors border border-slate-700 hover:border-slate-600"
              >
                Load More
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
