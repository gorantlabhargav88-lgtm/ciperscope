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
  EvidenceGraphResponse,
  Evidence,
  ChainOfCustodyEntry,
  CaseSummary,
  InvestigationSummary,
  InvestigationIntelligence,
  AnalystDecision,
  CaseTimelineEvent,
  ForensicTimelineEvent,
  ForensicReport,
  EvidenceVaultItem,
  EvidenceIntegrity,
  Webhook,
  WebhookWithSecret,
  WebhookEventType,
  CaseReport,
  CaseHistoryEntry,
  NetworkIntelligenceResponse,
  OrgIndicatorListResponse,
  AnalyticsOverview,
  AnalyticsRange,
  AuditLogListResponse,
  OrgMember,
  OrgMemberWithTempPassword,
  MemberListResponse,
  MemberRole,
  OrgSettingsResponse,
  UpdateOrgSettingsInput,
  AlertListResponse,
  AlertItem,
  CreatedInvitation,
  InvitationListResponse,
  InvitationPreview,
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
    // Only set Content-Type when there's an actual body — Fastify 5 rejects
    // a request declaring 'application/json' with no body
    // (FST_ERR_CTP_EMPTY_JSON_BODY), which every body-less POST (e.g.
    // testWebhook, createEmailReport) would otherwise hit.
    if (init.body !== undefined) headers.set('Content-Type', 'application/json');
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
   * Backend mapping (Phase 8): raw DkimVerification rows carry a `result`
   * field that can only be `'PASS'` when services/worker/src/verifier's
   * DkimVerifier performed a real RFC 6376 cryptographic verification
   * (services/worker/src/verifier/dkim/verifyCryptography.ts) — never from
   * signature presence, length, or syntactic validity alone. This method
   * derives `cryptographicallyVerified` from that honest `result` field
   * rather than trusting a separate backend-supplied flag, so callers have
   * one place to check before ever displaying a DKIM result as trustworthy.
   */
  async getEmailDkim(emailId: string): Promise<{ dkimVerifications: DkimResult[] }> {
    const raw = await this.request<{ dkimVerifications: Omit<DkimResult, 'cryptographicallyVerified'>[] }>(
      `/emails/${emailId}/dkim`
    );
    return {
      dkimVerifications: raw.dkimVerifications.map((v) => ({ ...v, cryptographicallyVerified: v.result === 'PASS' })),
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

  getEmailEvidenceGraph(emailId: string): Promise<EvidenceGraphResponse> {
    return this.request(`/emails/${emailId}/evidence-graph`);
  }

  // Phase J — forensic PDF reports
  createEmailReport(emailId: string): Promise<ForensicReport> {
    return this.request(`/emails/${emailId}/reports`, { method: 'POST' });
  }

  getEmailReports(emailId: string): Promise<{ reports: ForensicReport[] }> {
    return this.request(`/emails/${emailId}/reports`);
  }

  getReport(reportId: string): Promise<ForensicReport> {
    return this.request(`/reports/${reportId}`);
  }

  async downloadReport(reportId: string): Promise<Blob> {
    const fetchFn = this.config.fetchImpl ?? fetch;
    const headers = new Headers();
    const orgId = this.config.getOrganizationId();
    if (orgId) headers.set('x-organization-id', orgId);

    const response = await fetchFn(`${this.config.baseUrl}/reports/${reportId}/download`, {
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      if (response.status === 401) this.config.onUnauthorized?.();
      const body = await response.json().catch(() => ({}) as Record<string, unknown>);
      throw new ApiError(response.status, (body as { message?: string }).message || `API error: ${response.status}`);
    }

    return response.blob();
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

  async getGmailConnectionStatus(): Promise<
    | { status: 'not_connected' }
    | { status: 'connected'; emailAddress: string; connectedAt: string; lastUpdatedAt: string }
  > {
    return this.request('/integrations/gmail/connection');
  }

  // ============================================================
  // Evidence vault (org-wide) — services/api/src/modules/evidence/evidence.routes.ts
  // ============================================================

  getEvidenceList(limit = 20, cursor?: string): Promise<{ items: EvidenceVaultItem[]; nextCursor: string | null }> {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (cursor) qs.set('cursor', cursor);
    return this.request(`/evidence?${qs.toString()}`);
  }

  getEvidenceDetail(evidenceId: string): Promise<EvidenceVaultItem> {
    return this.request(`/evidence/${evidenceId}`);
  }

  getEvidenceIntegrity(evidenceId: string): Promise<EvidenceIntegrity> {
    return this.request(`/evidence/${evidenceId}/integrity`);
  }

  // ============================================================
  // Webhooks — services/api/src/modules/webhook/webhook.routes.ts
  // ============================================================

  getWebhooks(): Promise<{ webhooks: Webhook[] }> {
    return this.request('/webhooks');
  }

  createWebhook(input: { url: string; events: WebhookEventType[]; enabled?: boolean }): Promise<WebhookWithSecret> {
    return this.request('/webhooks', { method: 'POST', body: JSON.stringify(input) });
  }

  updateWebhook(
    webhookId: string,
    input: { url?: string; events?: WebhookEventType[]; enabled?: boolean }
  ): Promise<Webhook> {
    return this.request(`/webhooks/${webhookId}`, { method: 'PATCH', body: JSON.stringify(input) });
  }

  deleteWebhook(webhookId: string): Promise<null> {
    return this.request(`/webhooks/${webhookId}`, { method: 'DELETE' });
  }

  testWebhook(webhookId: string): Promise<{ message: string; eventId: string }> {
    return this.request(`/webhooks/${webhookId}/test`, { method: 'POST' });
  }

  // ============================================================
  // Case-scoped narrative reports — services/api/src/modules/case/case.routes.ts
  // ============================================================

  getCaseReports(caseId: string, limit = 20): Promise<{ items: CaseReport[]; nextCursor: string | null }> {
    return this.request(`/cases/${caseId}/reports?limit=${limit}`);
  }

  getCaseReport(caseId: string, reportId: string): Promise<CaseReport> {
    return this.request(`/cases/${caseId}/reports/${reportId}`);
  }

  createCaseReport(caseId: string, input: { title: string; contentHtml?: string }): Promise<CaseReport> {
    return this.request(`/cases/${caseId}/reports`, { method: 'POST', body: JSON.stringify(input) });
  }

  deleteCaseReport(caseId: string, reportId: string): Promise<null> {
    return this.request(`/cases/${caseId}/reports/${reportId}`, { method: 'DELETE' });
  }

  /** GET /cases/:caseId/history — the case record's own change/audit trail (status, priority, assignment). */
  getCaseHistory(caseId: string, limit = 20): Promise<{ items: CaseHistoryEntry[]; nextCursor: string | null }> {
    return this.request(`/cases/${caseId}/history?limit=${limit}`);
  }

  /** GET /intelligence/network — org-wide relay-hop IP aggregation (geolocation + classification + reverse DNS). Backs Geo Intelligence and Infrastructure. */
  getNetworkIntelligence(): Promise<NetworkIntelligenceResponse> {
    return this.request('/intelligence/network');
  }

  // ============================================================
  // Org-wide Indicators — services/api/src/modules/intelligence/intelligence.routes.ts
  // ============================================================

  getIndicators(params: {
    page?: number;
    limit?: number;
    q?: string;
    type?: string;
    severity?: string;
    source?: string;
    status?: string;
  } = {}): Promise<OrgIndicatorListResponse> {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', String(params.page));
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.q) qs.set('q', params.q);
    if (params.type) qs.set('type', params.type);
    if (params.severity) qs.set('severity', params.severity);
    if (params.source) qs.set('source', params.source);
    if (params.status) qs.set('status', params.status);
    const suffix = qs.toString();
    return this.request(`/intelligence/indicators${suffix ? `?${suffix}` : ''}`);
  }

  // ============================================================
  // Security Analytics — services/api/src/modules/analytics/analytics.routes.ts
  // ============================================================

  getAnalyticsOverview(range: AnalyticsRange = '30d'): Promise<AnalyticsOverview> {
    return this.request(`/analytics/overview?range=${range}`);
  }

  // ============================================================
  // Org-wide Audit Log — services/api/src/modules/audit/audit.routes.ts
  // ============================================================

  getAuditLog(params: {
    limit?: number;
    cursor?: string;
    action?: string;
    actorId?: string;
    resource?: string;
    resourceId?: string;
    dateFrom?: string;
    dateTo?: string;
    q?: string;
  } = {}): Promise<AuditLogListResponse> {
    const qs = new URLSearchParams();
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.cursor) qs.set('cursor', params.cursor);
    if (params.action) qs.set('action', params.action);
    if (params.actorId) qs.set('actorId', params.actorId);
    if (params.resource) qs.set('resource', params.resource);
    if (params.resourceId) qs.set('resourceId', params.resourceId);
    if (params.dateFrom) qs.set('dateFrom', params.dateFrom);
    if (params.dateTo) qs.set('dateTo', params.dateTo);
    if (params.q) qs.set('q', params.q);
    const suffix = qs.toString();
    return this.request(`/audit-log${suffix ? `?${suffix}` : ''}`);
  }

  // ============================================================
  // Users & Roles — services/api/src/modules/members/members.routes.ts
  // ============================================================

  getMembers(params: { limit?: number; cursor?: string; q?: string; roleId?: string; isActive?: boolean } = {}): Promise<MemberListResponse> {
    const qs = new URLSearchParams();
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.cursor) qs.set('cursor', params.cursor);
    if (params.q) qs.set('q', params.q);
    if (params.roleId) qs.set('roleId', params.roleId);
    if (params.isActive !== undefined) qs.set('isActive', String(params.isActive));
    const suffix = qs.toString();
    return this.request(`/members${suffix ? `?${suffix}` : ''}`);
  }

  getMember(memberId: string): Promise<OrgMember> {
    return this.request(`/members/${memberId}`);
  }

  getMemberRoles(): Promise<{ roles: MemberRole[] }> {
    return this.request('/members/roles');
  }

  createMember(input: { email: string; firstName?: string; lastName?: string; roleId: string }): Promise<OrgMemberWithTempPassword> {
    return this.request('/members', { method: 'POST', body: JSON.stringify(input) });
  }

  updateMember(memberId: string, input: { roleId?: string; isActive?: boolean }): Promise<OrgMember> {
    return this.request(`/members/${memberId}`, { method: 'PATCH', body: JSON.stringify(input) });
  }

  removeMember(memberId: string): Promise<null> {
    return this.request(`/members/${memberId}`, { method: 'DELETE' });
  }

  // ============================================================
  // Organization Settings — services/api/src/modules/settings/settings.routes.ts
  // ============================================================

  getOrgSettings(): Promise<OrgSettingsResponse> {
    return this.request('/settings');
  }

  updateOrgSettings(input: UpdateOrgSettingsInput): Promise<OrgSettingsResponse> {
    return this.request('/settings', { method: 'PATCH', body: JSON.stringify(input) });
  }

  // ============================================================
  // Alerts / Notifications — services/api/src/modules/alert/alert.routes.ts
  // ============================================================

  getAlerts(params: { limit?: number; cursor?: string; severity?: string; isRead?: boolean } = {}): Promise<AlertListResponse> {
    const qs = new URLSearchParams();
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.cursor) qs.set('cursor', params.cursor);
    if (params.severity) qs.set('severity', params.severity);
    if (params.isRead !== undefined) qs.set('isRead', String(params.isRead));
    const suffix = qs.toString();
    return this.request(`/alerts${suffix ? `?${suffix}` : ''}`);
  }

  getUnreadAlertCount(): Promise<{ count: number }> {
    return this.request('/alerts/unread-count');
  }

  markAlertRead(alertId: string): Promise<AlertItem> {
    return this.request(`/alerts/${alertId}`, { method: 'PATCH', body: JSON.stringify({ isRead: true }) });
  }

  markAllAlertsRead(): Promise<{ count: number }> {
    return this.request('/alerts/mark-all-read', { method: 'POST' });
  }

  // ============================================================
  // Invitations — services/api/src/modules/invitation/invitation.routes.ts
  // ============================================================

  createInvitation(input: { email: string; roleId: string }): Promise<CreatedInvitation> {
    return this.request('/invitations', { method: 'POST', body: JSON.stringify(input) });
  }

  getInvitations(params: { limit?: number; cursor?: string; status?: string } = {}): Promise<InvitationListResponse> {
    const qs = new URLSearchParams();
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.cursor) qs.set('cursor', params.cursor);
    if (params.status) qs.set('status', params.status);
    const suffix = qs.toString();
    return this.request(`/invitations${suffix ? `?${suffix}` : ''}`);
  }

  revokeInvitation(invitationId: string): Promise<null> {
    return this.request(`/invitations/${invitationId}`, { method: 'DELETE' });
  }

  resendInvitation(invitationId: string): Promise<CreatedInvitation> {
    return this.request(`/invitations/${invitationId}/resend`, { method: 'POST' });
  }

  /** Public — no organization header, the token itself is the credential. */
  getInvitationPreview(token: string): Promise<InvitationPreview> {
    return this.request(`/invitations/${token}`);
  }

  /** Public. When the invited email already has an account, this requires the caller to be authenticated as that user. */
  acceptInvitation(token: string, input: { password?: string; firstName?: string; lastName?: string }): Promise<{ status: string; organizationId: string }> {
    return this.request(`/invitations/${token}/accept`, { method: 'POST', body: JSON.stringify(input) });
  }

  // NOTE (Phase 3, Step 2): GET /emails/:emailId/analysis now returns
  // `caseId` (previously a documented missing capability — see git history
  // of this file / CIPERSCOPE_NEXT_PHASE_AUDIT.md). Callers should read
  // `email.caseId` from getEmailAnalysis() to decide whether to call
  // getCase / getCaseEvidenceList / getCaseInvestigations, rather than
  // requiring an external caseId to be supplied.
}
