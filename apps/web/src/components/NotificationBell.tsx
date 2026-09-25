import { useEffect, useRef, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Bell, Check, Loader2, Radio } from 'lucide-react';
import { apiClient, BASE_URL } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import { useAuth } from '../features/auth/AuthContext';
import type { AlertSeverityValue } from '@ciperscope/types';

const SEVERITY_DOT: Record<AlertSeverityValue, string> = {
  CRITICAL: 'bg-security-critical',
  HIGH: 'bg-security-high',
  MEDIUM: 'bg-security-medium',
  LOW: 'bg-security-low',
  INFO: 'bg-security-info',
};

type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'unavailable';

/**
 * Header notification bell — backed by the existing Alert model/API
 * (GET/PATCH /alerts, same data as the Alerts page). Real-time delivery is
 * Server-Sent Events (GET /alerts/stream — Redis pub/sub relayed from the
 * FusionEngine/gmail-sync Alert producers, see services/api/src/modules/
 * alert/notificationHub.ts); an SSE event never carries the notification
 * content itself, only a signal to refetch the one real data source
 * (GET /alerts), so there is no risk of the push channel and the REST
 * fetch ever showing different or duplicated data. Polling stays as a
 * fallback baseline (a much longer interval than before SSE existed) in
 * case the stream itself is unreachable — e.g. behind a proxy that blocks
 * long-lived connections — never the sole delivery mechanism.
 */
export const NotificationBell = () => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const { isAuthenticated, user } = useAuth();
  const organizationId = user?.organizationId;
  const [streamStatus, setStreamStatus] = useState<StreamStatus>('connecting');

  const { data: countData } = useQuery({
    queryKey: ['alerts-unread-count'],
    queryFn: () => apiClient.getUnreadAlertCount(),
    // SSE delivers unread-count-affecting events immediately; this interval
    // only exists as a fallback for when the stream is down.
    refetchInterval: streamStatus === 'live' ? 5 * 60_000 : 30_000,
  });

  const { data: listData, isLoading, error } = useQuery({
    queryKey: ['alerts-recent'],
    queryFn: () => apiClient.getAlerts({ limit: 8 }),
    enabled: open,
    refetchInterval: open && streamStatus !== 'live' ? 30_000 : false,
  });

  // Server-Sent Events connection — opened whenever there's an
  // authenticated org context, closed on logout/org change/unmount
  // (satisfies "logout closes the SSE connection": isAuthenticated
  // flipping to false re-runs this effect, and the cleanup below closes
  // the EventSource before a new one — none — is opened).
  useEffect(() => {
    if (!isAuthenticated || !organizationId) {
      setStreamStatus('unavailable');
      return;
    }

    setStreamStatus('connecting');
    const url = `${BASE_URL}/alerts/stream?organizationId=${encodeURIComponent(organizationId)}`;
    const source = new EventSource(url, { withCredentials: true });

    source.onopen = () => setStreamStatus('live');

    source.addEventListener('notification', (evt) => {
      try {
        const event = JSON.parse((evt as MessageEvent).data) as { type: string };
        if (event.type === 'ALERT_CREATED') {
          queryClient.invalidateQueries({ queryKey: ['alerts-unread-count'] });
          queryClient.invalidateQueries({ queryKey: ['alerts-recent'] });
        } else if (event.type === 'INVITATION_ACCEPTED') {
          // A real domain event (Users & Roles' pending-invitations list),
          // not backed by an Alert row — see invitation.routes.ts's accept
          // handler for why this doesn't also touch the alerts queries.
          queryClient.invalidateQueries({ queryKey: ['invitations'] });
          queryClient.invalidateQueries({ queryKey: ['members'] });
        }
      } catch {
        // malformed payload — never let it break the connection
      }
    });

    // The browser's EventSource retries automatically (honoring the
    // `retry:` field the server sends) — this only tracks status for the
    // "Live"/"Reconnecting" indicator below, never implements reconnection
    // logic itself.
    source.onerror = () => {
      setStreamStatus((prev) => (prev === 'connecting' ? 'unavailable' : 'reconnecting'));
    };

    return () => {
      source.close();
    };
  }, [isAuthenticated, organizationId, queryClient]);

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
              <p className="text-[11px] text-muted-foreground flex items-center gap-1">
                <Radio className={`w-2.5 h-2.5 ${streamStatus === 'live' ? 'text-security-low' : streamStatus === 'reconnecting' ? 'text-security-medium' : 'text-muted-foreground'}`} />
                {streamStatus === 'live' && 'Live'}
                {streamStatus === 'connecting' && 'Connecting…'}
                {streamStatus === 'reconnecting' && 'Reconnecting…'}
                {streamStatus === 'unavailable' && 'Polling · updates every 30s'}
              </p>
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
