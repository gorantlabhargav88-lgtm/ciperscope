import type {
  EmailAnalysisSummary,
  EmailHeader,
  EmailRelayHop,
  EmailMimePart,
  EmailUrlEntry,
  EmailAttachmentEntry,
  EmailAuthenticationSummary,
  SpfResult,
  DkimResult,
  DmarcResult,
  ThreatIndicator,
  EmailGeolocationEntry,
  Evidence,
  ChainOfCustodyEntry,
  CaseSummary,
  InvestigationSummary,
  InvestigationIntelligence,
  AnalystDecision,
  CaseTimelineEvent,
  ForensicTimelineEvent,
} from '@ciperscope/types';

export interface ApiClientConfig {
  baseUrl: string;
  getOrganizationId: () => string | null;
  /** Lets the host app react to a 401 (e.g. clear session state) without this package depending on the app's auth context. */
  onUnauthorized?: () => void;
  fetchImpl?: typeof fetch;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Raw shape of GET /emails/:emailId/ai-analysis's `prediction` field (MLInference row, or a NOT_AVAILABLE stub). */
export interface MlInferencePrediction {
  status?: string;
  message?: string;
  prediction?: string | null;
  modelScore?: number | null;
  modelName?: string | null;
  modelVersion?: string | null;
  artifactSha256?: string | null;
}

/** Raw AuditLog row shape returned by GET .../investigations/:id/decisions — see case.routes.ts:2534-2544. */
interface RawDecisionAuditLogEntry {
  id: string;
  actorId: string | null;
  createdAt: string;
  metadata?: {
    targetId?: string;
    targetType?: string;
    decision?: AnalystDecision['decision'];
    reason?: string;
  } | null;
}

/**
 * Typed client for the existing CiperScope API — implements ONLY endpoints
 * that already exist in services/api/src/modules/*. See the "MISSING
 * BACKEND CAPABILITY" comments below for gaps found while building this;
 * none of those were invented as fake endpoints.
 */
export class CiperscopeApiClient {
  constructor(private readonly config: ApiClientConfig) {}

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const fetchFn = this.config.fetchImpl ?? fetch;
    const headers = new Headers(init.headers);
    headers.set('Content-Type', 'application/json');
    const orgId = this.config.getOrganizationId();
    if (orgId) headers.set('x-organization-id', orgId);

    const response = await fetchFn(`${this.config.baseUrl}${path}`, {
      ...init,
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      if (response.status === 401) this.config.onUnauthorized?.();
      const body = await response.json().catch(() => ({}) as Record<string, unknown>);
      throw new ApiError(response.status, (body as { message?: string }).message || `API error: ${response.status}`);
    }

    if (response.status === 204) return null as T;
    return response.json() as Promise<T>;
  }

  // ============================================================
  // Email forensics — services/api/src/modules/email/email.routes.ts
  // ============================================================

  getEmailAnalysis(emailId: string): Promise<EmailAnalysisSummary> {
    return this.request(`/emails/${emailId}/analysis`);
  }

  getEmailHeaders(emailId: string): Promise<{ headers: EmailHeader[] }> {
    return this.request(`/emails/${emailId}/headers`);
  }

  getEmailReceivedHops(emailId: string): Promise<{ hops: EmailRelayHop[] }> {
    return this.request(`/emails/${emailId}/received-hops`);
  }

  getEmailMimeParts(emailId: string): Promise<{ mimeParts: EmailMimePart[] }> {
    return this.request(`/emails/${emailId}/mime-parts`);
  }

  getEmailAuthenticationSummary(emailId: string): Promise<{ analysis: EmailAuthenticationSummary | null }> {
    return this.request(`/emails/${emailId}/authentication`);
  }

  getEmailSpf(emailId: string): Promise<{ spfVerifications: SpfResult[] }> {
    return this.request(`/emails/${emailId}/spf`);
  }

  /**
   * Backend mapping (Phase 2C): raw DkimVerification rows have no field
   * disclosing that CiperScope's DKIM check is simulated, not cryptographic
   * (services/worker/src/verifier/DkimVerifier.ts:67-110). This method
   * injects `cryptographicallyVerified: false` on every row so callers can
   * never accidentally display a DKIM result as trustworthy — the backend
   * field names themselves are left untouched.
   */
  async getEmailDkim(emailId: string): Promise<{ dkimVerifications: DkimResult[] }> {
    const raw = await this.request<{ dkimVerifications: Omit<DkimResult, 'cryptographicallyVerified'>[] }>(
      `/emails/${emailId}/dkim`
    );
    return {
      dkimVerifications: raw.dkimVerifications.map((v) => ({ ...v, cryptographicallyVerified: false as const })),
    };
  }

  getEmailDmarc(emailId: string): Promise<{ dmarcVerification: DmarcResult | null }> {
    return this.request(`/emails/${emailId}/dmarc`);
  }

  getEmailUrls(emailId: string): Promise<{ urls: EmailUrlEntry[] }> {
    return this.request(`/emails/${emailId}/urls`);
  }

  getEmailAttachments(emailId: string): Promise<{ attachments: EmailAttachmentEntry[] }> {
    return this.request(`/emails/${emailId}/attachments`);
  }

  getEmailAiAnalysis(emailId: string): Promise<{ status?: string; prediction: MlInferencePrediction }> {
    return this.request(`/emails/${emailId}/ai-analysis`);
  }

  getEmailThreatIndicators(emailId: string): Promise<{ threatIndicators: ThreatIndicator[] }> {
    return this.request(`/emails/${emailId}/threat-indicators`);
  }

  getEmailGeolocation(emailId: string): Promise<{ geolocation: EmailGeolocationEntry[] }> {
    return this.request(`/emails/${emailId}/geolocation`);
  }

  async ingestEmail(file: File): Promise<{ message: string; emailId?: string; duplicate?: boolean }> {
    const fetchFn = this.config.fetchImpl ?? fetch;
    const formData = new FormData();
    formData.append('file', file);
    const headers = new Headers();
    const orgId = this.config.getOrganizationId();
    if (orgId) headers.set('x-organization-id', orgId);

    const response = await fetchFn(`${this.config.baseUrl}/emails/ingest`, {
      method: 'POST',
      headers,
      body: formData,
      credentials: 'include',
    });
    const data = await response.json().catch(() => ({}) as Record<string, unknown>);
    if (!response.ok) {
      if (response.status === 401) this.config.onUnauthorized?.();
      throw new ApiError(response.status, (data as { message?: string }).message || 'Upload failed');
    }
    return data as { message: string; emailId?: string; duplicate?: boolean };
  }

  // ============================================================
  // Case-scoped evidence & investigation — services/api/src/modules/case/case.routes.ts
  // ============================================================

  getCase(caseId: string): Promise<CaseSummary> {
    return this.request(`/cases/${caseId}`);
  }

  getCaseEvidenceList(caseId: string, limit = 20): Promise<{ items: Evidence[]; nextCursor: string | null }> {
    return this.request(`/cases/${caseId}/evidence?limit=${limit}`);
  }

  getCaseEvidence(caseId: string, evidenceId: string): Promise<Evidence> {
    return this.request(`/cases/${caseId}/evidence/${evidenceId}`);
  }

  getEvidenceCustody(caseId: string, evidenceId: string): Promise<{ items: ChainOfCustodyEntry[] }> {
    return this.request(`/cases/${caseId}/evidence/${evidenceId}/custody`);
  }

  getCaseInvestigations(
    caseId: string,
    limit = 20
  ): Promise<{ items: InvestigationSummary[]; nextCursor?: string }> {
    return this.request(`/cases/${caseId}/investigations?limit=${limit}`);
  }

  getInvestigationIntelligence(caseId: string, investigationId: string): Promise<InvestigationIntelligence> {
    return this.request(`/cases/${caseId}/investigations/${investigationId}/intelligence`);
  }

  /**
   * GET /cases/:caseId/timeline — the case's own AuditLog-backed activity
   * trail (see CaseTimelineEvent doc comment for exactly what this does
   * and does not include).
   */
  getCaseTimeline(caseId: string, limit = 50): Promise<{ items: CaseTimelineEvent[]; nextCursor: string | null }> {
    return this.request(`/cases/${caseId}/timeline?limit=${limit}`);
  }

  /**
   * GET /cases/:caseId/forensic-timeline — the correlated, multi-source
   * unified timeline (Phase 5). Not paginated on the backend today; see
   * that route's EVENT_CAP bounds for the known limitation.
   */
  getCaseForensicTimeline(caseId: string): Promise<{ items: ForensicTimelineEvent[] }> {
    return this.request(`/cases/${caseId}/forensic-timeline`);
  }

  /**
   * Backend mapping (Phase 2C): GET .../decisions returns raw AuditLog rows
   * ({ decisions: [...] }, event-sourced — see case.routes.ts:2534-2544)
   * with the actual decision fields nested under `metadata`, not a
   * dedicated Decision table. This method maps that shape into the
   * cleaner AnalystDecision contract; the backend field names/response
   * envelope are otherwise left untouched.
   */
  async getInvestigationDecisions(caseId: string, investigationId: string): Promise<{ items: AnalystDecision[] }> {
    const raw = await this.request<{ decisions: RawDecisionAuditLogEntry[] }>(
      `/cases/${caseId}/investigations/${investigationId}/decisions`
    );
    return {
      items: raw.decisions.map((d) => ({
        id: d.id,
        targetId: d.metadata?.targetId ?? '',
        targetType: d.metadata?.targetType ?? '',
        decision: d.metadata?.decision ?? 'REVIEWED',
        reason: d.metadata?.reason,
        actorId: d.actorId ?? undefined,
        createdAt: d.createdAt,
      })),
    };
  }

  /**
   * POST /:caseId/investigations/:investigationId/decisions
   * (services/api/src/modules/case/case.routes.ts:2444-2506). Requires
   * CASE_UPDATE, exactly as the backend enforces — this method does not
   * weaken or bypass that check.
   */
  async recordAnalystDecision(
    caseId: string,
    investigationId: string,
    input: { targetId: string; targetType: string; decision: AnalystDecision['decision']; reason?: string }
  ): Promise<{ status: string; targetId: string; decision: string }> {
    return this.request(`/cases/${caseId}/investigations/${investigationId}/decisions`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  /**
   * DELETE /integrations/gmail/connection (Phase 7B). Requires
   * INTEGRATION_MANAGE, enforced server-side. Never returns tokens — only
   * a status summary.
   */
  async disconnectGmail(): Promise<{ status: string; count?: number }> {
    return this.request('/integrations/gmail/connection', { method: 'DELETE' });
  }

  // NOTE (Phase 3, Step 2): GET /emails/:emailId/analysis now returns
  // `caseId` (previously a documented missing capability — see git history
  // of this file / CIPERSCOPE_NEXT_PHASE_AUDIT.md). Callers should read
  // `email.caseId` from getEmailAnalysis() to decide whether to call
  // getCase / getCaseEvidenceList / getCaseInvestigations, rather than
  // requiring an external caseId to be supplied.
}
