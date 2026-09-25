/**
 * Organization Users & Roles — GET/POST/PATCH/DELETE /members
 * (services/api/src/modules/members/members.routes.ts). Reuses the
 * existing User/OrganizationMember/Role/Permission tables; never a
 * duplicate user model.
 */
export interface MemberRole {
  id: string;
  name: string;
  description: string | null;
}

export interface OrgMember {
  id: string;
  userId: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  isActive: boolean;
  lastLoginAt: string | null;
  joinedAt: string;
  role: MemberRole;
}

/** Only present in the POST /members response, and only once — see members.routes.ts. */
export interface OrgMemberWithTempPassword extends OrgMember {
  temporaryPassword?: string;
}

export interface MemberListResponse {
  items: OrgMember[];
  nextCursor: string | null;
}
