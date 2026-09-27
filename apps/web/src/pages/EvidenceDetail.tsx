import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Loader2,
  AlertTriangle,
  ShieldOff,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  HelpCircle,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Clock,
} from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError, type ClassifiedApiError } from '../lib/apiErrorState';
import type { EvidenceVaultItem, EvidenceIntegrity } from '@ciperscope/types';

const STATUS_DISPLAY: Record<EvidenceIntegrity['status'], { label: string; className: string; icon: typeof ShieldCheck }> = {
  VALID: { label: 'Valid', className: 'bg-security-verified/10 text-security-verified border-security-verified/20', icon: ShieldCheck },
  INVALID: { label: 'Invalid — possible tampering', className: 'bg-security-critical/10 text-security-critical border-security-critical/20', icon: ShieldAlert },
  INCOMPLETE: { label: 'Incomplete', className: 'bg-security-info/10 text-security-info border-security-info/20', icon: ShieldQuestion },
  NOT_CONFIGURED: { label: 'Not configured', className: 'bg-slate-800 text-slate-400 border-slate-700', icon: HelpCircle },
};

const ANCHOR_STATUS_STYLES: Record<string, { label: string; className: string; icon: typeof ShieldCheck }> = {
  ANCHORED: { label: 'Anchored on-chain', className: 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60', icon: CheckCircle2 },
  BATCHED: { label: 'Batched in Merkle tree', className: 'bg-blue-950/40 text-blue-400 border-blue-800/60', icon: Clock },
  HASHED: { label: 'Hashed — awaiting batching', className: 'bg-amber-950/40 text-amber-400 border-amber-800/60', icon: ShieldQuestion },
  FAILED: { label: 'Anchoring failed', className: 'bg-rose-950/40 text-rose-400 border-rose-800/60', icon: XCircle },
  NOT_CONFIGURED: { label: 'Not configured', className: 'bg-slate-800/60 text-slate-400 border-slate-700', icon: HelpCircle },
};

function getExplorerTxUrl(network: string | null | undefined, txHash: string | null | undefined): string | null {
  if (!txHash) return null;
  const net = (network || 'sepolia').toLowerCase();
  if (net === 'sepolia') return `https://sepolia.etherscan.io/tx/${txHash}`;
  if (net === 'holesky') return `https://holesky.etherscan.io/tx/${txHash}`;
  if (net === 'mainnet') return `https://etherscan.io/tx/${txHash}`;
  return `https://sepolia.etherscan.io/tx/${txHash}`;
}

function getExplorerAddressUrl(network: string | null | undefined, address: string | null | undefined): string | null {
  if (!address) return null;
  const net = (network || 'sepolia').toLowerCase();
  if (net === 'sepolia') return `https://sepolia.etherscan.io/address/${address}`;
  if (net === 'holesky') return `https://holesky.etherscan.io/address/${address}`;
  if (net === 'mainnet') return `https://etherscan.io/address/${address}`;
  return `https://sepolia.etherscan.io/address/${address}`;
}

/**
 * Per-evidence detail + integrity verification (GET /evidence/:id,
 * GET /evidence/:id/integrity). Cryptographic hash + chain-of-custody
 * + Merkle batch + real blockchain-anchor verification.
 * Displays only authentic on-chain transactions and block explorer links.
 */
export const EvidenceDetail = () => {
  const { id } = useParams<{ id: string }>();
  const [evidence, setEvidence] = useState<EvidenceVaultItem | null>(null);
  const [integrity, setIntegrity] = useState<EvidenceIntegrity | null>(null);
  const [state, setState] = useState<'loading' | 'loaded' | 'error'>('loading');
  const [classified, setClassified] = useState<ClassifiedApiError | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setState('loading');
    Promise.all([apiClient.getEvidenceDetail(id), apiClient.getEvidenceIntegrity(id)])
      .then(([evidenceRes, integrityRes]) => {
        if (cancelled) return;
        setEvidence(evidenceRes);
        setIntegrity(integrityRes);
        setState('loaded');
      })
      .catch((err) => {
        if (cancelled) return;
        setClassified(classifyApiError(err, 'evidence record'));
        setState('error');
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (state === 'loading') {
    return (
      <div className="flex justify-center items-center py-20">
        <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (state === 'error' || !evidence || !integrity) {
    return (
      <div className="space-y-6">
        <Link to="/evidence" className="inline-flex items-center text-sm text-slate-400 hover:text-slate-200">
          <ArrowLeft className="w-4 h-4 mr-1" /> Back to Evidence Vault
        </Link>
        <div
          className={`border p-6 rounded-xl flex items-center gap-4 ${
            classified?.kind === 'unauthorized' || classified?.kind === 'forbidden'
              ? 'bg-amber-950/30 border-amber-900/50'
              : 'bg-red-950/30 border-red-900/50'
          }`}
        >
          {classified?.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified?.kind === 'forbidden' ? 'Access denied' : 'Failed to load evidence'}</h3>
            <p className="text-sm text-slate-400">{classified?.message ?? 'Evidence record not found.'}</p>
          </div>
        </div>
      </div>
    );
  }

  const statusDisplay = STATUS_DISPLAY[integrity.status];
  const StatusIcon = statusDisplay.icon;

  const anchorStatusConfig = ANCHOR_STATUS_STYLES[integrity.anchorStatus] || {
    label: integrity.anchorStatus,
    className: 'bg-slate-800 text-slate-400 border-slate-700',
    icon: HelpCircle,
  };
  const AnchorStatusIcon = anchorStatusConfig.icon;

  const txUrl = getExplorerTxUrl(integrity.network, integrity.transactionId);
  const contractUrl = getExplorerAddressUrl(integrity.network, integrity.contractAddress);

  return (
    <div className="space-y-6 pb-20">
      <Link to="/evidence" className="inline-flex items-center text-sm text-slate-400 hover:text-slate-200">
        <ArrowLeft className="w-4 h-4 mr-1" /> Back to Evidence Vault
      </Link>

      <header className="border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-white tracking-tight">{evidence.filename ?? 'Unnamed evidence'}</h1>
        <p className="text-slate-500 font-mono text-xs mt-1">{evidence.id}</p>
      </header>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Evidence Metadata */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Evidence Metadata</h2>
          <dl className="text-sm space-y-2">
            <div className="flex justify-between">
              <dt className="text-slate-500">Type</dt>
              <dd className="text-slate-300">{evidence.type}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">Status</dt>
              <dd className="text-slate-300">{evidence.status}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">MIME type</dt>
              <dd className="text-slate-300">{evidence.mimeType ?? 'Unknown'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">Size</dt>
              <dd className="text-slate-300">{evidence.sizeBytes != null ? `${(evidence.sizeBytes / 1024).toFixed(1)} KB` : 'Unknown'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">Collected</dt>
              <dd className="text-slate-300">{new Date(evidence.collectionTime).toLocaleString()}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">Source system</dt>
              <dd className="text-slate-300">{evidence.sourceSystem ?? 'Unknown'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500">SHA-256</dt>
              <dd className="text-slate-300 font-mono text-xs break-all text-right max-w-[220px]">{evidence.sha256}</dd>
            </div>
            <div className="flex justify-between pt-2 border-t border-slate-800">
              <dt className="text-slate-500">Case</dt>
              <dd>
                <Link to={`/cases/${evidence.caseId}`} className="text-blue-400 hover:text-blue-300">
                  View case
                </Link>
              </dd>
            </div>
            {evidence.relatedEmailId && (
              <div className="flex justify-between pt-2 border-t border-slate-800">
                <dt className="text-slate-500">Forensics</dt>
                <dd>
                  <Link to={`/email-analysis/${evidence.relatedEmailId}`} className="text-blue-400 hover:text-blue-300">
                    Analyze email
                  </Link>
                </dd>
              </div>
            )}
          </dl>
        </div>

        {/* Integrity Verification Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-300 mb-3">Integrity Verification</h2>
            <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium mb-3 ${statusDisplay.className}`}>
              <StatusIcon className="w-4 h-4" /> {statusDisplay.label}
            </div>
            <p className="text-xs text-slate-400">{integrity.reason}</p>
          </div>

          <dl className="text-sm space-y-2 border-t border-slate-800 pt-3">
            <div className="flex justify-between">
              <dt className="text-slate-500">Chain of custody</dt>
              <dd className={integrity.chainValid ? 'text-security-verified' : 'text-security-critical'}>
                {integrity.chainValid ? 'Valid' : integrity.chainReason ?? 'Invalid'}
              </dd>
            </div>

            <div className="flex justify-between">
              <dt className="text-slate-500">Merkle batch</dt>
              <dd className="text-slate-300">
                {integrity.merkleValid === 'NOT_BATCHED' ? 'Not batched' : integrity.merkleValid ? 'Verified' : 'Failed'}
              </dd>
            </div>

            <div className="flex justify-between items-center">
              <dt className="text-slate-500">Blockchain anchor</dt>
              <dd className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${anchorStatusConfig.className}`}>
                <AnchorStatusIcon className="w-3.5 h-3.5" />
                <span>{anchorStatusConfig.label}</span>
              </dd>
            </div>

            {integrity.network && (
              <div className="flex justify-between">
                <dt className="text-slate-500">Network</dt>
                <dd className="text-slate-300 uppercase tracking-wide text-xs font-mono">{integrity.network}</dd>
              </div>
            )}

            {integrity.contractAddress && (
              <div className="flex justify-between items-center">
                <dt className="text-slate-500">Contract</dt>
                <dd className="text-slate-300 font-mono text-xs break-all text-right max-w-[220px]">
                  {contractUrl ? (
                    <a
                      href={contractUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 inline-flex items-center gap-1"
                    >
                      <span className="truncate max-w-[170px]">{integrity.contractAddress}</span>
                      <ExternalLink className="w-3 h-3 flex-shrink-0" />
                    </a>
                  ) : (
                    integrity.contractAddress
                  )}
                </dd>
              </div>
            )}

            {integrity.transactionId && (
              <div className="flex justify-between items-center">
                <dt className="text-slate-500">Transaction</dt>
                <dd className="text-slate-300 font-mono text-xs break-all text-right max-w-[220px]">
                  {txUrl ? (
                    <a
                      href={txUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 inline-flex items-center gap-1"
                    >
                      <span className="truncate max-w-[170px]">{integrity.transactionId}</span>
                      <ExternalLink className="w-3 h-3 flex-shrink-0" />
                    </a>
                  ) : (
                    integrity.transactionId
                  )}
                </dd>
              </div>
            )}

            {integrity.blockNumber != null && (
              <div className="flex justify-between">
                <dt className="text-slate-500">Block height</dt>
                <dd className="text-slate-300 font-mono text-xs">#{integrity.blockNumber.toLocaleString()}</dd>
              </div>
            )}

            {integrity.anchoredAt && (
              <div className="flex justify-between">
                <dt className="text-slate-500">Anchored at</dt>
                <dd className="text-slate-400 text-xs">{new Date(integrity.anchoredAt).toLocaleString()}</dd>
              </div>
            )}

            <div className="flex justify-between pt-2 border-t border-slate-800">
              <dt className="text-slate-500">Verified at</dt>
              <dd className="text-slate-400 text-xs">{new Date(integrity.verifiedAt).toLocaleString()}</dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
};
