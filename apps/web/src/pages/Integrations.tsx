import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { useSearchParams } from 'react-router-dom';
import { Mail, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '../components/ui/alert';
import { apiClient } from '../lib/apiClient';

// Matches apps/web/src/lib/apiClient.ts's own BASE_URL derivation.
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1';

type ConnectionState =
  | { kind: 'loading' }
  | { kind: 'not_connected' }
  | { kind: 'connected'; emailAddress: string; connectedAt: string };

export default function Integrations() {
  const [searchParams] = useSearchParams();
  // Transient banner for the one-time OAuth redirect (?integration=success|error)
  // — separate from `connection`, which is the actual, refresh-proof source
  // of truth for whether Gmail is connected (fetched from the backend, not
  // inferred from a URL param that disappears after the first render).
  const [banner, setBanner] = useState<'success' | 'error' | null>(null);
  const [connection, setConnection] = useState<ConnectionState>({ kind: 'loading' });
  const [disconnecting, setDisconnecting] = useState(false);
  const [disconnectError, setDisconnectError] = useState<string | null>(null);

  const loadStatus = async () => {
    try {
      const res = await apiClient.getGmailConnectionStatus();
      setConnection(
        res.status === 'connected'
          ? { kind: 'connected', emailAddress: res.emailAddress, connectedAt: res.connectedAt }
          : { kind: 'not_connected' }
      );
    } catch {
      // Honest unknown rather than fabricating a connected/not-connected
      // state — render the not-connected UI (safe default: offers "Connect"
      // rather than falsely claiming an active connection) and let the user
      // retry.
      setConnection({ kind: 'not_connected' });
    }
  };

  useEffect(() => {
    const integrationStatus = searchParams.get('integration');
    if (integrationStatus === 'success') setBanner('success');
    else if (integrationStatus === 'error') setBanner('error');
    loadStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const handleDisconnect = async () => {
    if (disconnecting) return;
    setDisconnecting(true);
    setDisconnectError(null);
    try {
      await apiClient.disconnectGmail();
      setBanner(null);
      await loadStatus();
    } catch (err) {
      setDisconnectError(err instanceof Error ? err.message : 'Failed to disconnect Gmail');
    } finally {
      setDisconnecting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Integrations</h2>
        <p className="text-muted-foreground">
          Connect external services to automatically ingest data for threat analysis.
        </p>
      </div>

      {banner === 'success' && (
        <Alert className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>
            Successfully connected to Gmail. CiperScope is now automatically monitoring your inbox for threats.
          </AlertDescription>
        </Alert>
      )}

      {banner === 'error' && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>
            Failed to connect to Gmail. Please try again.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card className="flex flex-col h-full bg-card/50 backdrop-blur-sm border-white/10 hover:border-white/20 transition-all duration-300">
          <CardHeader>
            <div className="flex items-center justify-between mb-2">
              <div className="h-12 w-12 rounded-xl bg-blue-500/10 flex items-center justify-center border border-blue-500/20">
                <Mail className="h-6 w-6 text-blue-400" />
              </div>
              <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20">
                OAuth 2.0
              </Badge>
            </div>
            <CardTitle>Google Workspace / Gmail</CardTitle>
            <CardDescription>
              Automatically ingest and scan incoming emails for phishing attempts, malicious attachments, and IOCs.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex-grow">
            <ul className="text-sm text-muted-foreground space-y-2">
              <li className="flex items-center"><CheckCircle2 className="mr-2 h-4 w-4 text-emerald-500" /> Real-time push notifications</li>
              <li className="flex items-center"><CheckCircle2 className="mr-2 h-4 w-4 text-emerald-500" /> Automatic async processing</li>
              <li className="flex items-center"><CheckCircle2 className="mr-2 h-4 w-4 text-emerald-500" /> Tenant isolated</li>
            </ul>
            {connection.kind === 'connected' && (
              <p className="text-xs text-muted-foreground mt-4 pt-4 border-t border-white/10">
                Connected as <span className="text-foreground font-medium">{connection.emailAddress}</span>
                <br />
                since {new Date(connection.connectedAt).toLocaleDateString()}
              </p>
            )}
          </CardContent>
          <CardFooter className="flex-col gap-2 items-stretch">
            {connection.kind === 'loading' ? (
              <Button variant="outline" className="w-full" disabled>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Checking status…
              </Button>
            ) : connection.kind === 'connected' ? (
              <>
                <Button variant="outline" className="w-full" disabled>
                  Connected
                </Button>
                <Button
                  variant="destructive"
                  className="w-full"
                  disabled={disconnecting}
                  onClick={handleDisconnect}
                >
                  {disconnecting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {disconnecting ? 'Disconnecting…' : 'Disconnect'}
                </Button>
                {disconnectError && <p className="text-xs text-destructive">{disconnectError}</p>}
              </>
            ) : (
              <Button
                className="w-full bg-blue-600 hover:bg-blue-700 text-white shadow-[0_0_15px_rgba(37,99,235,0.3)] hover:shadow-[0_0_25px_rgba(37,99,235,0.5)] transition-all duration-300"
                onClick={() => { window.location.href = `${API_BASE_URL}/integrations/gmail/auth`; }}
              >
                Connect Gmail
              </Button>
            )}
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
