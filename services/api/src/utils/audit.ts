import { prisma } from '@ciperscope/database';
import { FastifyRequest } from 'fastify';
import { getRequestContext, logger } from '@ciperscope/logger';

export type AuditAction = 
  | 'AUTH_LOGIN'
  | 'AUTH_REFRESH'
  | 'AUTH_LOGOUT'
  | 'AUTHZ_DENIED'
  | 'EMAIL_INGESTED'
  | 'EMAIL_ANALYSIS_VIEWED'
  | 'EMAIL_HEADERS_VIEWED'
  | 'EMAIL_RECEIVED_HOPS_VIEWED'
  | 'EMAIL_MIME_PARTS_VIEWED'
  | 'EMAIL_AUTH_VIEWED'
  | 'EMAIL_SPF_VIEWED'
  | 'EMAIL_DKIM_VIEWED'
  | 'EMAIL_DMARC_VIEWED'
  | 'EMAIL_THREAT_INDICATORS_VIEWED'
  | 'EMAIL_GEOLOCATION_VIEWED'
  | 'EMAIL_ATTACHMENT_VIEWED'
  | 'EMAIL_AI_ANALYSIS_VIEWED';

export type AuditStatus = 'SUCCESS' | 'FAILURE' | 'DENIED';

export interface AuditEventPayload {
  action: AuditAction;
  resource: string;
  resourceId?: string;
  status: AuditStatus;
  organizationId?: string;
  actorId?: string;
  metadata?: Record<string, any>;
  req?: FastifyRequest;
}

export async function logAuditEvent(payload: AuditEventPayload) {
  try {
    const actorId = payload.actorId || payload.req?.user?.sub || null;
    const organizationId = payload.organizationId || (payload.req?.headers['x-organization-id'] as string) || null;
    const ipAddress = payload.req?.ip || null;
    const userAgent = payload.req?.headers['user-agent']?.substring(0, 255) || null;
    
    // Grab the request ID / trace ID from async context if available
    const context = getRequestContext();
    const traceId = context?.traceId;
    const requestId = payload.req?.id;

    const safeMetadata = {
      ...payload.metadata,
      traceId,
      requestId
    };

    // Ensure we NEVER log raw passwords or tokens by explicitly excluding known bad keys
    const scrubbedMetadata = scrubMetadata(safeMetadata);

    await prisma.auditLog.create({
      data: {
        organizationId,
        actorId,
        action: payload.action,
        resource: payload.resource,
        resourceId: payload.resourceId,
        status: payload.status,
        ipAddress,
        userAgent,
        metadata: scrubbedMetadata
      }
    });
  } catch (error) {
    // Audit failure policy:
    // For this system, we log the failure to standard out so it hits APM, 
    // but we do NOT crash the process unless it's a critical mutation.
    // Given the architecture, falling back to a structured application log
    // ensures the forensic trail isn't entirely lost even if Postgres is down.
    logger.error({ 
      err: error, 
      auditAction: payload.action,
      auditActor: payload.actorId || payload.req?.user?.sub,
      auditResource: payload.resourceId
    }, 'CRITICAL: Failed to write database audit log. Falling back to application log.');
    
    // For highly sensitive evidence access, we might want to throw to FAIL CLOSED.
    // "High-value forensic evidence access may require stronger guarantees"
    if (payload.action.includes('VIEWED') || payload.action === 'AUTH_LOGIN') {
      // Fail open for normal app usage? The prompt asks us to consider it.
      // We will throw to ensure FAIL CLOSED for sensitive viewing/auth.
      throw new Error('Audit logging failed. Secure action aborted.');
    }
  }
}

function scrubMetadata(meta: any): any {
  if (!meta) return meta;
  const scrubbed = { ...meta };
  const sensitiveKeys = ['password', 'token', 'jwt', 'cookie', 'authorization', 'raw', 'body', 'secret', 'key'];
  
  for (const key of Object.keys(scrubbed)) {
    if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
      scrubbed[key] = '***REDACTED***';
    } else if (typeof scrubbed[key] === 'object' && scrubbed[key] !== null) {
      scrubbed[key] = scrubMetadata(scrubbed[key]);
    }
  }
  return scrubbed;
}
