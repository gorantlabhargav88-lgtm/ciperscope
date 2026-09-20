import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { useSearchParams } from 'react-router-dom';
import { Mail, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '../components/ui/alert';
import { apiClient } from '../lib/apiClient';

export default function Integrations() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [disconnecting, setDisconnecting] = useState(false);
  const [disconnectError, setDisconnectError] = useState<string | null>(null);

  useEffect(() => {
    const integrationStatus = searchParams.get('integration');
    if (integrationStatus === 'success') {
      setStatus('success');
    } else if (integrationStatus === 'error') {
      setStatus('error');
    }
  }, [searchParams]);

  const handleDisconnect = async () => {
    if (disconnecting) return;
    setDisconnecting(true);
    setDisconnectError(null);
    try {
      await apiClient.disconnectGmail();
      setStatus('idle');
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

      {status === 'success' && (
        <Alert className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>
            Successfully connected to Gmail. CiperScope is now automatically monitoring your inbox for threats.
          </AlertDescription>
        </Alert>
      )}

      {status === 'error' && (
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
          </CardContent>
          <CardFooter className="flex-col gap-2 items-stretch">
            {status === 'success' ? (
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
                onClick={() => window.location.href = 'http://localhost:3000/api/v1/integrations/gmail/auth'}
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
