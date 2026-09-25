/**
 * A role is assignable within an organization if it belongs to that org, OR
 * it's a true platform-wide system role (Role.organizationId === null,
 * isSystem === true — e.g. the seeded "SYSTEM_ADMIN" role; see
 * packages/database/prisma/seed.ts). Global roles can only ever be
 * provisioned by direct database/seed administration — there is no
 * endpoint that lets any tenant create one — so trusting an existing
 * global role's id here does not weaken tenant isolation or open a
 * privilege-escalation path.
 *
 * Shared by members.routes.ts and invitation.routes.ts — both need to
 * validate a client-supplied roleId against the same "does this role
 * belong here" rule.
 */
export function roleVisibleToOrgWhere(organizationId: string) {
  return { OR: [{ organizationId }, { organizationId: null, isSystem: true }] };
}
