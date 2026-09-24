import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Loader2, AlertTriangle, ShieldOff, ShieldCheck, ShieldAlert, ShieldQuestion, HelpCircle } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError, type ClassifiedApiError } from '../lib/apiErrorState';
import type { EvidenceVaultItem, EvidenceIntegrity } from '@ciperscope/types';

const STATUS_DISPLAY: Record<EvidenceIntegrity['status'], { label: string; className: string; icon: typeof ShieldCheck }> = {
  VALID: { label: 'Valid', className: 'bg-security-verified/10 text-security-verified border-security-verified/20', icon: ShieldCheck },
  INVALID: { label: 'Invalid — possible tampering', className: 'bg-security-critical/10 text-security-critical border-security-critical/20', icon: ShieldAlert },
  INCOMPLETE: { label: 'Incomplete', className: 'bg-security-info/10 text-security-info border-security-info/20', icon: ShieldQuestion },
  NOT_CONFIGURED: { label: 'Not configured', className: 'bg-slate-800 text-slate-400 border-slate-700', icon: HelpCircle },
};

/**
 * Per-evidence detail + integrity verification (GET /evidence/:id,
 * GET /evidence/:id/integrity). This is the real backend for what the
 * "Verification" nav item promises — cryptographic hash + chain-of-custody
 * + (if batched) Merkle/blockchain-anchor verification, never a fabricated
 * "verified" claim for a stage that wasn't actually checked.
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
        <Link to="/evidence" className="inline-flex items-center text-sm text-slate-400 hover:text-slate-200"><ArrowLeft className="w-4 h-4 mr-1" /> Back to Evidence Vault</Link>
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified?.kind === 'unauthorized' || classified?.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
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

  return (
    <div className="space-y-6 pb-20">
      <Link to="/evidence" className="inline-flex items-center text-sm text-slate-400 hover:text-slate-200"><ArrowLeft className="w-4 h-4 mr-1" /> Back to Evidence Vault</Link>

      <header className="border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-white tracking-tight">{evidence.filename ?? 'Unnamed evidence'}</h1>
        <p className="text-slate-500 font-mono text-xs mt-1">{evidence.id}</p>
      </header>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Evidence Metadata</h2>
          <dl className="text-sm space-y-2">
            <div className="flex justify-between"><dt className="text-slate-500">Type</dt><dd className="text-slate-300">{evidence.type}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Status</dt><dd className="text-slate-300">{evidence.status}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">MIME type</dt><dd className="text-slate-300">{evidence.mimeType ?? 'Unknown'}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Size</dt><dd className="text-slate-300">{evidence.sizeBytes != null ? `${(evidence.sizeBytes / 1024).toFixed(1)} KB` : 'Unknown'}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Collected</dt><dd className="text-slate-300">{new Date(evidence.collectionTime).toLocaleString()}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Source system</dt><dd className="text-slate-300">{evidence.sourceSystem ?? 'Unknown'}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">SHA-256</dt><dd className="text-slate-300 font-mono text-xs break-all text-right max-w-[220px]">{evidence.sha256}</dd></div>
            <div className="flex justify-between pt-2 border-t border-slate-800">
              <dt className="text-slate-500">Case</dt>
              <dd><Link to={`/cases/${evidence.caseId}`} className="text-blue-400 hover:text-blue-300">View case</Link></dd>
            </div>
          </dl>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Integrity Verification</h2>
          <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium mb-4 ${statusDisplay.className}`}>
            <StatusIcon className="w-4 h-4" /> {statusDisplay.label}
          </div>
          <p className="text-sm text-slate-400 mb-4">{integrity.reason}</p>
          <dl className="text-sm space-y-2">
            <div className="flex justify-between"><dt className="text-slate-500">Chain of custody</dt><dd className={integrity.chainValid ? 'text-security-verified' : 'text-security-critical'}>{integrity.chainValid ? 'Valid' : (integrity.chainReason ?? 'Invalid')}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Merkle batch</dt><dd className="text-slate-300">{integrity.merkleValid === 'NOT_BATCHED' ? 'Not batched' : integrity.merkleValid ? 'Verified' : 'Failed'}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Blockchain anchor</dt><dd className="text-slate-300">{integrity.anchorStatus}</dd></div>
            {integrity.network && (
              <div className="flex justify-between"><dt className="text-slate-500">Network</dt><dd className="text-slate-300">{integrity.network}</dd></div>
            )}
            {integrity.transactionId && (
              <div className="flex justify-between"><dt className="text-slate-500">Transaction</dt><dd className="text-slate-300 font-mono text-xs break-all text-right max-w-[220px]">{integrity.transactionId}</dd></div>
            )}
            <div className="flex justify-between pt-2 border-t border-slate-800"><dt className="text-slate-500">Verified at</dt><dd className="text-slate-400 text-xs">{new Date(integrity.verifiedAt).toLocaleString()}</dd></div>
          </dl>
        </div>
      </div>
    </div>
  );
};
