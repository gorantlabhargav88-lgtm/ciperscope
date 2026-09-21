import type { AnalystDecision, ForensicTimelineEvent } from '@ciperscope/types';

const NOT_AVAILABLE = 'Not available';

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-300 text-right break-all">{value ?? NOT_AVAILABLE}</span>
    </div>
  );
}

/**
 * Category-aware detail panel for a timeline event's real metadata. Only
 * renders fields that are actually present in `event.metadata` (populated
 * server-side in services/api's forensic-timeline route) — every missing
 * field shows "Not available" rather than a fabricated placeholder.
 */
export function EventDetailPanel({ event, decision }: { event: ForensicTimelineEvent; decision: AnalystDecision | null }) {
  const meta = (event.metadata ?? {}) as Record<string, unknown>;

  return (
    <div className="px-3 pb-3 space-y-3 text-[11px]">
      <div className="bg-slate-900 border border-slate-800 rounded p-2">
        {event.category === 'EMAIL' && (
          <>
            <Row label="Email ID" value={event.emailId} />
            <Row label="Sender" value={(meta.senderAddress as string) ?? null} />
            <Row label="Classification" value={(meta.classification as string) ?? null} />
            <Row label="Severity" value={event.severity} />
            <Row label="Priority" value={event.priority?.priority ?? null} />
          </>
        )}

        {event.category === 'AUTHENTICATION' && (
          <>
            <Row label="SPF" value={(meta.spf as string) ?? null} />
            <Row label="DMARC" value={(meta.dmarc as string) ?? null} />
            <Row label="DKIM" value={(meta.dkim as string) ?? null} />
            {meta.dkimCryptographicallyVerified ? (
              <div className="mt-1 text-emerald-500">DKIM signature cryptographically verified.</div>
            ) : (
              <div className="mt-1 text-amber-500">DKIM cryptographic verification did not succeed.</div>
            )}
          </>
        )}

        {event.category === 'THREAT_INTELLIGENCE' && event.action === 'CTI_ENRICHED' && (
          <>
            <Row label="Indicator" value={event.resourceId} />
            <Row label="Provider" value={event.source} />
            <Row label="Verdict" value={(meta.verdict as string) ?? null} />
            <Row label="Confidence" value={meta.confidence != null ? `${meta.confidence}%` : null} />
          </>
        )}
        {event.category === 'THREAT_INTELLIGENCE' && event.action === 'THREAT_SCORE_CALCULATED' && (
          <>
            <Row label="Overall Score" value={meta.overallScore != null ? String(meta.overallScore) : null} />
            <Row label="Risk Level" value={(meta.riskLevel as string) ?? null} />
            <Row label="Priority" value={event.priority?.priority ?? null} />
            <Row label="Source" value={event.source} />
          </>
        )}

        {event.category === 'ML' && (
          <>
            <Row label="Model" value={event.source} />
            <Row label="Model Score" value={meta.modelScore != null ? String(meta.modelScore) : null} />
            <Row label="Model Version" value={(meta.modelVersion as string) ?? null} />
            <Row label="Artifact SHA-256" value={(meta.artifactSha256 as string) ?? null} />
          </>
        )}

        {event.category === 'INVESTIGATION' && (
          <>
            <Row label="Investigation ID" value={event.investigationId} />
            <Row label="Timestamp" value={event.timestamp ? new Date(event.timestamp).toLocaleString() : null} />
          </>
        )}

        {event.category === 'EVIDENCE' && (
          <>
            <Row label="Evidence ID" value={event.evidenceId} />
            <Row label="Action" value={event.action} />
            <Row label="SHA-256" value={(meta.sha256 as string) ?? null} />
            {event.actor && <Row label="Actor" value={[event.actor.firstName, event.actor.lastName].filter(Boolean).join(' ') || event.actor.email} />}
          </>
        )}

        {event.category === 'ANALYST' && (
          <>
            <Row label="Action" value={event.action} />
            {event.actor && <Row label="Actor" value={[event.actor.firstName, event.actor.lastName].filter(Boolean).join(' ') || event.actor.email} />}
            <Row label="Note" value={event.description} />
          </>
        )}

        {event.category === 'SYSTEM' && (
          <>
            <Row label="Action" value={event.action} />
            {event.actor && <Row label="Actor" value={[event.actor.firstName, event.actor.lastName].filter(Boolean).join(' ') || event.actor.email} />}
          </>
        )}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded p-2">
        <div className="text-slate-400 font-medium mb-1">Analyst Decision</div>
        {decision ? (
          <>
            <Row label="Decision" value={decision.decision} />
            <Row label="Actor" value={decision.actorId} />
            <Row label="Timestamp" value={decision.createdAt ? new Date(decision.createdAt).toLocaleString() : null} />
            {decision.reason && <Row label="Note" value={decision.reason} />}
          </>
        ) : (
          <div className="text-slate-600">No analyst decision recorded</div>
        )}
      </div>
    </div>
  );
}
