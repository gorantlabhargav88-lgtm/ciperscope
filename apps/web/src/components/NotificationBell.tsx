import { useEffect, useRef, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Bell, Check, Loader2 } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import type { AlertSeverityValue } from '@ciperscope/types';

const SEVERITY_DOT: Record<AlertSeverityValue, string> = {
  CRITICAL: 'bg-security-critical',
  HIGH: 'bg-security-high',
  MEDIUM: 'bg-security-medium',
  LOW: 'bg-security-low',
  INFO: 'bg-security-info',
};

/**
 * Header notification bell — backed by the existing Alert model/API
 * (GET/PATCH /alerts, same data as the Alerts page). No WebSocket/SSE/
 * pub-sub infrastructure exists anywhere in this codebase (confirmed by
 * repository inspection), so this polls on an interval rather than
 * fabricating a live push channel — the "Polling" label below is honest
 * about that, never presented as realtime.
 */
export const NotificationBell = () => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  const { data: countData } = useQuery({
    queryKey: ['alerts-unread-count'],
    queryFn: () => apiClient.getUnreadAlertCount(),
    refetchInterval: 30_000,
  });

  const { data: listData, isLoading, error } = useQuery({
    queryKey: ['alerts-recent'],
    queryFn: () => apiClient.getAlerts({ limit: 8 }),
    enabled: open,
    refetchInterval: open ? 30_000 : false,
  });

  const markReadMutation = useMutation({
    mutationFn: (alertId: string) => apiClient.markAlertRead(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts-recent'] });
      queryClient.invalidateQueries({ queryKey: ['alerts-unread-count'] });
    },
  });

  const markAllReadMutation = useMutation({
    mutationFn: () => apiClient.markAllAlertsRead(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts-recent'] });
      queryClient.invalidateQueries({ queryKey: ['alerts-unread-count'] });
    },
  });

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', handler);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handler);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  const unreadCount = countData?.count ?? 0;
  const classified = error ? classifyApiError(error, 'notifications') : null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={unreadCount > 0 ? `Notifications, ${unreadCount} unread` : 'Notifications'}
        aria-expanded={open}
        aria-haspopup="true"
        className="relative text-muted-foreground hover:text-foreground transition-colors"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute -top-1.5 -right-1.5 min-w-[16px] h-4 px-1 rounded-full bg-security-critical text-white text-[10px] font-medium flex items-center justify-center">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Notifications"
          className="absolute right-0 top-full mt-2 w-80 max-w-[calc(100vw-2rem)] bg-popover border border-border rounded-lg shadow-2xl z-20 overflow-hidden"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div>
              <h3 className="text-sm font-medium text-foreground">Notifications</h3>
              <p className="text-[11px] text-muted-foreground">Polling · updates every 30s</p>
            </div>
            {unreadCount > 0 && (
              <button
                onClick={() => markAllReadMutation.mutate()}
                disabled={markAllReadMutation.isPending}
                className="text-xs text-primary hover:underline disabled:opacity-50 flex items-center gap-1"
              >
                {markAllReadMutation.isPending && <Loader2 className="w-3 h-3 animate-spin" />}
                Mark all read
              </button>
            )}
          </div>

          <div className="max-h-96 overflow-y-auto">
            {isLoading ? (
              <div className="flex justify-center py-8">
                <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
              </div>
            ) : classified ? (
              <div className="p-4 text-xs text-muted-foreground">{classified.message}</div>
            ) : !listData || listData.items.length === 0 ? (
              <div className="p-6 text-center text-sm text-muted-foreground">No notifications yet.</div>
            ) : (
              <ul>
                {listData.items.map((a) => (
                  <li key={a.id} role="menuitem" className={`border-b border-border/60 last:border-0 ${a.isRead ? 'opacity-60' : ''}`}>
                    <div className="px-4 py-3 flex items-start gap-2.5 hover:bg-accent/40 transition-colors">
                      <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${SEVERITY_DOT[a.severity]}`} aria-hidden="true" />
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium text-foreground truncate">{a.title}</p>
                        <p className="text-xs text-muted-foreground line-clamp-2 mt-0.5">{a.message}</p>
                        <div className="flex items-center justify-between mt-1.5">
                          <span className="text-[10px] text-muted-foreground">{new Date(a.createdAt).toLocaleString()}</span>
                          <div className="flex items-center gap-2">
                            {a.caseId && (
                              <Link to={`/cases/${a.caseId}`} onClick={() => setOpen(false)} className="text-[10px] text-primary hover:underline">
                                View case
                              </Link>
                            )}
                            {!a.isRead && (
                              <button
                                onClick={() => markReadMutation.mutate(a.id)}
                                aria-label="Mark as read"
                                className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5"
                              >
                                <Check className="w-3 h-3" /> Read
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <Link
            to="/alerts"
            onClick={() => setOpen(false)}
            className="block text-center text-xs text-primary hover:underline py-2.5 border-t border-border"
          >
            View all alerts
          </Link>
        </div>
      )}
    </div>
  );
};
