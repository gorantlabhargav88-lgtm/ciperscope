import { prisma } from '@ciperscope/database';

/**
 * The same session-revocation check rbac.ts's `authenticate` hook performs
 * after `request.jwtVerify()`, extracted so the SSE notification stream
 * route (services/api/src/modules/alert/alert.routes.ts's GET /alerts/
 * stream) — which authenticates manually because EventSource cannot use
 * Fastify's normal preValidation array cleanly alongside its raw-stream
 * response handling — applies the identical check rather than a
 * second, possibly-divergent one.
 */
export async function isSessionValid(sessionId: string): Promise<boolean> {
  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  return Boolean(session && session.isValid);
}
