import { prisma } from '@ciperscope/database';

/**
 * The raw DB check behind rbac.ts's requirePermission() hook, extracted so
 * a second call site can reuse the exact same authorization logic without
 * risking it drifting out of sync. Needed for the SSE notification stream
 * (services/api/src/modules/alert/alert.routes.ts's GET /alerts/stream):
 * browsers' EventSource API cannot send custom headers, so tenant context
 * for that one route arrives as a query param instead of the usual
 * x-organization-id header — this function lets that route apply the
 * identical membership+permission check regardless of where the org id
 * came from, rather than writing a second, possibly-divergent check.
 */
export async function userHasPermissionInOrg(userId: string, organizationId: string, action: string): Promise<boolean> {
  const membership = await prisma.organizationMember.findUnique({
    where: { userId_organizationId: { userId, organizationId } },
    include: { role: { include: { permissions: { include: { permission: true } } } } },
  });
  if (!membership) return false;
  return membership.role.permissions.some((rp) => rp.permission.action === action);
}
