import { z } from 'zod';
import zodToJsonSchema from 'zod-to-json-schema';

// Centralized UUID validation for all IDs
export const uuidSchema = z.string().uuid('Invalid UUID format');

// Parameters for typical single-email routes
export const EmailParamsSchema = z.object({
  emailId: uuidSchema,
});

// Parameters for attachment routes
export const AttachmentParamsSchema = z.object({
  emailId: uuidSchema,
  attachmentId: uuidSchema,
});

// Organization Header validation (using passthrough to ignore other headers Fastify might receive)
export const OrgHeaderSchema = z.object({
  'x-organization-id': uuidSchema,
}).passthrough();

// Fastify-compatible JSON schemas
export const fastifyEmailParamsSchema = zodToJsonSchema(EmailParamsSchema as any);
export const fastifyAttachmentParamsSchema = zodToJsonSchema(AttachmentParamsSchema as any);
export const fastifyOrgHeaderSchema = zodToJsonSchema(OrgHeaderSchema as any);

// Case Management
export const CreateCaseBodySchema = z.object({
  title: z.string().max(255),
  description: z.string().max(4000).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
}).strict(); // Using .strict() equivalent to additionalProperties: false

export const fastifyCreateCaseBodySchema = zodToJsonSchema(CreateCaseBodySchema as any);

export const CaseParamsSchema = z.object({
  caseId: uuidSchema,
});

export const CaseListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
  q: z.string().max(255).optional(),
  status: z.enum(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED']).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  assigneeId: uuidSchema.optional(),
  createdFrom: z.string().datetime().optional(),
  createdTo: z.string().datetime().optional(),
  sort: z.enum(['createdAt', 'updatedAt', 'priority', 'status']).default('createdAt'),
  direction: z.enum(['asc', 'desc']).default('desc'),
}).strict();

export const fastifyCaseParamsSchema = zodToJsonSchema(CaseParamsSchema as any);
export const fastifyCaseListQuerySchema = zodToJsonSchema(CaseListQuerySchema as any);

export const UpdateCaseBodySchema = z.object({
  title: z.string().max(255).optional(),
  description: z.string().max(4000).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  status: z.enum(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED']).optional(),
}).strict();

export const fastifyUpdateCaseBodySchema = zodToJsonSchema(UpdateCaseBodySchema as any);

export const AssignCaseBodySchema = z.object({
  assignedUserId: uuidSchema.nullable(),
}).strict();

export const fastifyAssignCaseBodySchema = zodToJsonSchema(AssignCaseBodySchema as any);

export const LinkCaseEmailBodySchema = z.object({
  emailId: uuidSchema,
}).strict();

export const fastifyLinkCaseEmailBodySchema = zodToJsonSchema(LinkCaseEmailBodySchema as any);

export const CreateCaseNoteBodySchema = z.object({
  content: z.string().min(1).max(4000),
}).strict();

export const fastifyCreateCaseNoteBodySchema = zodToJsonSchema(CreateCaseNoteBodySchema as any);

export const CaseNoteListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
}).strict();

export const fastifyCaseNoteListQuerySchema = zodToJsonSchema(CaseNoteListQuerySchema as any);

export const CaseTimelineQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
}).strict();

export const fastifyCaseTimelineQuerySchema = zodToJsonSchema(CaseTimelineQuerySchema as any);

export const CaseEmailListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
}).strict();

export const fastifyCaseEmailListQuerySchema = zodToJsonSchema(CaseEmailListQuerySchema as any);

export const CaseEmailParamsSchema = z.object({
  caseId: uuidSchema,
  emailId: uuidSchema,
});

export const fastifyCaseEmailParamsSchema = zodToJsonSchema(CaseEmailParamsSchema as any);

export const CaseHistoryQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
  action: z.enum([
    'CASE_CREATED',
    'CASE_VIEWED',
    'CASE_UPDATED',
    'CASE_ASSIGNED',
    'CASE_EMAIL_LINKED',
    'CASE_EMAIL_UNLINKED',
    'CASE_NOTE_ADDED',
    'CASE_NOTE_UPDATED',
    'CASE_NOTE_DELETED'
  ]).optional()
}).strict();

export const fastifyCaseHistoryQuerySchema = zodToJsonSchema(CaseHistoryQuerySchema as any);

export const CaseNoteParamsSchema = z.object({
  caseId: uuidSchema,
  noteId: uuidSchema,
});

export const fastifyCaseNoteParamsSchema = zodToJsonSchema(CaseNoteParamsSchema as any);

export const UpdateCaseNoteBodySchema = z.object({
  content: z.string().min(1).max(4000).regex(/\S/, 'Content cannot be empty whitespace'),
}).strict();

export const fastifyUpdateCaseNoteBodySchema = zodToJsonSchema(UpdateCaseNoteBodySchema as any);

export const CreateEvidenceBodySchema = z.object({
  type: z.enum(['RAW_EMAIL', 'HEADER', 'ATTACHMENT', 'URL', 'IP', 'DOMAIN', 'SCREENSHOT', 'REPORT', 'LOG', 'OTHER']),
  storageKey: z.string().min(1).refine(val => !val.includes('..') && !val.startsWith('/'), 'Invalid storage path'),
  filename: z.string().min(1).optional(),
  mimeType: z.string().min(1).optional(),
  sizeBytes: z.number().int().min(0).optional(),
  sha256: z.string().length(64).regex(/^[a-f0-9]{64}$/i, 'Must be a 64-character hex string')
});
export const fastifyCreateEvidenceBodySchema = zodToJsonSchema(CreateEvidenceBodySchema as any);

export const EvidenceListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().optional()
});
export const fastifyEvidenceListQuerySchema = zodToJsonSchema(EvidenceListQuerySchema as any);

export const EvidenceParamsSchema = z.object({
  caseId: uuidSchema,
  evidenceId: uuidSchema
});
export const fastifyEvidenceParamsSchema = zodToJsonSchema(EvidenceParamsSchema as any);

export const GlobalEvidenceParamsSchema = z.object({
  evidenceId: uuidSchema
});
export const fastifyGlobalEvidenceParamsSchema = zodToJsonSchema(GlobalEvidenceParamsSchema as any);

export const InvestigationListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().optional()
});
export const fastifyInvestigationListQuerySchema = zodToJsonSchema(InvestigationListQuerySchema as any);

export const InvestigationParamsSchema = z.object({
  caseId: uuidSchema,
  investigationId: uuidSchema
});
export const fastifyInvestigationParamsSchema = zodToJsonSchema(InvestigationParamsSchema as any);

export const GlobalInvestigationParamsSchema = z.object({
  investigationId: uuidSchema
});
export const fastifyGlobalInvestigationParamsSchema = zodToJsonSchema(GlobalInvestigationParamsSchema as any);

export const CreateInvestigationBodySchema = z.object({
  title: z.string().min(1).max(255).regex(/\S/, 'Title cannot be empty whitespace'),
  description: z.string().max(4000).optional()
}).strict();
export const fastifyCreateInvestigationBodySchema = zodToJsonSchema(CreateInvestigationBodySchema as any);

export const UpdateInvestigationBodySchema = z.object({
  title: z.string().min(1).max(255).regex(/\S/, 'Title cannot be empty whitespace').optional(),
  description: z.string().max(4000).optional()
}).strict();
export const fastifyUpdateInvestigationBodySchema = zodToJsonSchema(UpdateInvestigationBodySchema as any);

export const CustodyListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().optional()
});
export const fastifyCustodyListQuerySchema = zodToJsonSchema(CustodyListQuerySchema as any);

export const createReportBodySchema = z.object({
  title: z.string().min(1).max(255),
  contentHtml: z.string().max(1000000).optional(),
  storageKey: z.string().max(1024).optional()
});
export const fastifyCreateReportBodySchema = zodToJsonSchema(createReportBodySchema as any);

export const ReportListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().optional(),
  sort: z.enum(['createdAt']).default('createdAt'),
  direction: z.enum(['asc', 'desc']).default('desc')
});
export const fastifyReportListQuerySchema = zodToJsonSchema(ReportListQuerySchema as any);

export const ReportParamsSchema = z.object({
  caseId: uuidSchema,
  reportId: uuidSchema
});
export const fastifyReportParamsSchema = zodToJsonSchema(ReportParamsSchema as any);

export const AlertListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().optional(),
  severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  isRead: z.enum(['true', 'false']).transform((val) => val === 'true').optional(),
  sort: z.enum(['createdAt']).default('createdAt'),
  direction: z.enum(['asc', 'desc']).default('desc')
});
export const fastifyAlertListQuerySchema = zodToJsonSchema(AlertListQuerySchema as any);

export const AlertParamsSchema = z.object({
  caseId: uuidSchema,
  alertId: uuidSchema
});
export const fastifyAlertParamsSchema = zodToJsonSchema(AlertParamsSchema as any);

export const GlobalAlertParamsSchema = z.object({
  alertId: uuidSchema
});
export const fastifyGlobalAlertParamsSchema = zodToJsonSchema(GlobalAlertParamsSchema as any);

export const UpdateAlertBodySchema = z.object({
  isRead: z.boolean()
});
export const fastifyUpdateAlertBodySchema = zodToJsonSchema(UpdateAlertBodySchema as any);

export const AlertUnreadCountQuerySchema = z.object({
  severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
}).strict();
export const fastifyAlertUnreadCountQuerySchema = zodToJsonSchema(AlertUnreadCountQuerySchema as any);

// SSE notification stream — organizationId arrives as a query param
// because the browser's EventSource API cannot send custom headers (so
// the usual x-organization-id header is unavailable here). Still fully
// validated against the authenticated user's real org memberships in the
// route handler — never trusted on its own. See alert.routes.ts's
// GET /alerts/stream.
export const AlertStreamQuerySchema = z.object({
  organizationId: uuidSchema,
}).strict();
export const fastifyAlertStreamQuerySchema = zodToJsonSchema(AlertStreamQuerySchema as any);

// Phase 2: outbound webhook management
export const WEBHOOK_EVENT_TYPES = ['THREAT_ANALYSIS_COMPLETED'] as const;

export const CreateWebhookBodySchema = z.object({
  url: z.string().url('Invalid webhook URL'),
  events: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1, 'At least one event type is required'),
  enabled: z.boolean().optional().default(true),
});
export const fastifyCreateWebhookBodySchema = zodToJsonSchema(CreateWebhookBodySchema as any);

export const UpdateWebhookBodySchema = z.object({
  url: z.string().url('Invalid webhook URL').optional(),
  events: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1).optional(),
  enabled: z.boolean().optional(),
}).refine((v) => v.url !== undefined || v.events !== undefined || v.enabled !== undefined, {
  message: 'At least one field must be provided',
});
export const fastifyUpdateWebhookBodySchema = zodToJsonSchema(UpdateWebhookBodySchema as any);

export const WebhookParamsSchema = z.object({
  webhookId: uuidSchema,
});
export const fastifyWebhookParamsSchema = zodToJsonSchema(WebhookParamsSchema as any);

// Phase J: email-centric forensic PDF reports (distinct from the
// case-centric ReportParamsSchema/createReportBodySchema above).
export const GlobalForensicReportParamsSchema = z.object({
  reportId: uuidSchema,
});
export const fastifyGlobalForensicReportParamsSchema = zodToJsonSchema(GlobalForensicReportParamsSchema as any);

// Org-wide Indicators (GET /intelligence/indicators)
export const IndicatorListQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(10000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  q: z.string().max(255).optional(),
  type: z.enum(['IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL_ADDRESS']).optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  source: z.string().max(100).optional(),
  status: z.enum(['CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN']).optional(),
}).strict();
export const fastifyIndicatorListQuerySchema = zodToJsonSchema(IndicatorListQuerySchema as any);

// Org-wide Security Analytics (GET /analytics/overview)
export const AnalyticsOverviewQuerySchema = z.object({
  range: z.enum(['24h', '7d', '30d', '90d']).default('30d'),
}).strict();
export const fastifyAnalyticsOverviewQuerySchema = zodToJsonSchema(AnalyticsOverviewQuerySchema as any);

// Org-wide Audit Log (GET /audit-log)
export const AuditLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().optional(),
  action: z.string().max(100).optional(),
  actorId: uuidSchema.optional(),
  resource: z.string().max(100).optional(),
  resourceId: z.string().max(255).optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional(),
  q: z.string().max(255).optional(),
}).strict();
export const fastifyAuditLogQuerySchema = zodToJsonSchema(AuditLogQuerySchema as any);

// Organization Members (Users & Roles)
export const MemberListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().optional(),
  q: z.string().max(255).optional(),
  roleId: uuidSchema.optional(),
  isActive: z.enum(['true', 'false']).optional(),
}).strict();
export const fastifyMemberListQuerySchema = zodToJsonSchema(MemberListQuerySchema as any);

export const MemberParamsSchema = z.object({
  memberId: uuidSchema,
});
export const fastifyMemberParamsSchema = zodToJsonSchema(MemberParamsSchema as any);

export const CreateMemberBodySchema = z.object({
  email: z.string().email().max(255),
  firstName: z.string().max(100).optional(),
  lastName: z.string().max(100).optional(),
  roleId: uuidSchema,
}).strict();
export const fastifyCreateMemberBodySchema = zodToJsonSchema(CreateMemberBodySchema as any);

export const UpdateMemberBodySchema = z.object({
  roleId: uuidSchema.optional(),
  isActive: z.boolean().optional(),
}).strict().refine((v) => v.roleId !== undefined || v.isActive !== undefined, {
  message: 'At least one field must be provided',
});
export const fastifyUpdateMemberBodySchema = zodToJsonSchema(UpdateMemberBodySchema as any);

// Organization Settings
export const UpdateOrgSettingsBodySchema = z.object({
  // Organization profile
  displayName: z.string().min(1).max(255).optional(),
  // Notification preferences — gates whether webhook-backed notification
  // events are considered "enabled" at the org level; the webhooks
  // themselves remain individually toggleable (see Webhook.enabled).
  notifyOnCriticalCase: z.boolean().optional(),
  notifyOnThreatDetected: z.boolean().optional(),
  // Threat-analysis preferences — the minimum risk level that
  // automatically opens a Case from an analyzed email (consumed by the
  // worker's case-auto-creation logic, see services/worker).
  autoCaseRiskThreshold: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'NEVER']).optional(),
  // Retention — no automated purge job exists today; this is stored and
  // surfaced honestly as a preference, never presented as an enforced
  // retention guarantee until a real enforcement job exists.
  evidenceRetentionDays: z.coerce.number().int().min(30).max(3650).optional(),
}).strict().refine((v) => Object.keys(v).length > 0, { message: 'At least one setting must be provided' });
export const fastifyUpdateOrgSettingsBodySchema = zodToJsonSchema(UpdateOrgSettingsBodySchema as any);

// Organization Invitations (Phase 3)
export const CreateInvitationBodySchema = z.object({
  email: z.string().email().max(255),
  roleId: uuidSchema,
}).strict();
export const fastifyCreateInvitationBodySchema = zodToJsonSchema(CreateInvitationBodySchema as any);

export const InvitationListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().optional(),
  status: z.enum(['PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED']).optional(),
}).strict();
export const fastifyInvitationListQuerySchema = zodToJsonSchema(InvitationListQuerySchema as any);

export const InvitationParamsSchema = z.object({
  invitationId: uuidSchema,
});
export const fastifyInvitationParamsSchema = zodToJsonSchema(InvitationParamsSchema as any);

export const InvitationTokenParamsSchema = z.object({
  token: z.string().min(32).max(128),
});
export const fastifyInvitationTokenParamsSchema = zodToJsonSchema(InvitationTokenParamsSchema as any);

export const AcceptInvitationBodySchema = z.object({
  // Only required when accepting as a brand-new account (no existing User
  // for the invited email) — enforced in the route handler, not here,
  // since that depends on a DB lookup the schema can't see.
  password: z.string().min(12).max(1024).optional(),
  firstName: z.string().max(100).optional(),
  lastName: z.string().max(100).optional(),
}).strict();
export const fastifyAcceptInvitationBodySchema = zodToJsonSchema(AcceptInvitationBodySchema as any);
