import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FastifyRequest } from 'fastify';
import { logAuditEvent } from '../../src/utils/audit';
import { prisma } from '@ciperscope/database';

vi.mock('@ciperscope/database', () => ({
  prisma: {
    auditLog: {
      create: vi.fn()
    }
  }
}));

vi.mock('@ciperscope/logger', () => ({
  getRequestContext: vi.fn(() => ({ traceId: 'test-trace-123' })),
  logger: {
    error: vi.fn()
  }
}));

describe('Audit Logger', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should scrub sensitive fields from metadata', async () => {
    const req = {
      ip: '1.2.3.4',
      user: { sub: 'user-1' },
      headers: { 'x-organization-id': 'org-1', 'user-agent': 'test-agent' },
      id: 'req-1'
    } as unknown as FastifyRequest;

    await logAuditEvent({
      action: 'AUTH_LOGIN',
      resource: 'Auth',
      status: 'SUCCESS',
      req,
      metadata: {
        safeField: 'hello',
        password: 'my-secret-password',
        token: 'ey.jwt.token',
        nested: {
          secretKey: '12345'
        }
      }
    });

    expect(prisma.auditLog.create).toHaveBeenCalledOnce();
    const callArg = vi.mocked(prisma.auditLog.create).mock.calls[0][0];
    
    expect(callArg.data.metadata).toEqual({
      safeField: 'hello',
      password: '***REDACTED***',
      token: '***REDACTED***',
      nested: {
        secretKey: '***REDACTED***'
      },
      traceId: 'test-trace-123',
      requestId: 'req-1'
    });
    
    expect(callArg.data.actorId).toBe('user-1');
    expect(callArg.data.organizationId).toBe('org-1');
  });

  it('should fail closed for sensitive actions if database throws', async () => {
    vi.mocked(prisma.auditLog.create).mockRejectedValueOnce(new Error('DB Down'));

    await expect(logAuditEvent({
      action: 'EMAIL_ANALYSIS_VIEWED',
      resource: 'Email',
      status: 'SUCCESS'
    })).rejects.toThrow('Audit logging failed. Secure action aborted.');
  });
  
  it('should fail open for non-sensitive actions if database throws', async () => {
    vi.mocked(prisma.auditLog.create).mockRejectedValueOnce(new Error('DB Down'));

    await expect(logAuditEvent({
      action: 'EMAIL_INGESTED',
      resource: 'Email',
      status: 'SUCCESS'
    })).resolves.toBeUndefined();
  });
});
