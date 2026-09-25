/**
 * Organization invitations — services/api/src/modules/invitation/
 * invitation.routes.ts. No SMTP/email provider exists in this repository,
 * so the create response includes `devOnlyInviteUrl` outside production
 * only — never presented as real email delivery.
 */
export type InvitationStatusValue = 'PENDING' | 'ACCEPTED' | 'EXPIRED' | 'REVOKED';
export type InvitationEmailStatusValue = 'NOT_CONFIGURED' | 'SENT' | 'FAILED';

export interface InvitationItem {
  id: string;
  organizationId: string;
  email: string;
  roleId: string;
  status: InvitationStatusValue;
  invitedById: string | null;
  expiresAt: string;
  acceptedAt: string | null;
  createdAt: string;
  emailStatus: InvitationEmailStatusValue;
  emailError: string | null;
  supersedesId: string | null;
  role: { id: string; name: string };
}

export interface CreatedInvitation extends InvitationItem {
  /** Present only when NODE_ENV !== 'production' — see the backend route's doc comment. */
  devOnlyInviteUrl?: string;
}

export interface InvitationListResponse {
  items: InvitationItem[];
  nextCursor: string | null;
}

export interface InvitationPreview {
  email: string;
  organizationName: string;
  roleName: string;
  expiresAt: string;
  /** True when no account exists yet for this email — the accept form must collect a password. */
  requiresPassword: boolean;
}
