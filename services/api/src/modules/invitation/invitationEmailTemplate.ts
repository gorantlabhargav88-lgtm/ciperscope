/**
 * CipherScope invitation email — plain-generated HTML/text, no external
 * templating engine (one email, not worth a new dependency). Every value
 * interpolated here is either server-controlled (organization name, role
 * name, expiry) or the invitee's own email address — never attacker-
 * controlled content, so this doesn't carry the injection risk that
 * templating raw email/attachment content would.
 */
export interface InvitationEmailInput {
  organizationName: string;
  invitedEmail: string;
  roleName: string;
  expiresAt: Date;
  acceptUrl: string;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function buildInvitationEmail(input: InvitationEmailInput): { subject: string; html: string; text: string } {
  const org = escapeHtml(input.organizationName);
  const role = escapeHtml(input.roleName);
  const expiry = input.expiresAt.toUTCString();

  const subject = `You've been invited to join ${input.organizationName} on CipherScope`;

  const html = `<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background-color:#020617;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#020617;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background-color:#0f172a;border:1px solid #1e293b;border-radius:12px;overflow:hidden;">
            <tr>
              <td style="padding:32px 32px 16px 32px;text-align:center;">
                <div style="font-size:20px;font-weight:700;color:#f1f5f9;">CipherScope</div>
                <div style="font-size:13px;color:#64748b;margin-top:4px;">See the Threat. Trace the Evidence.</div>
              </td>
            </tr>
            <tr>
              <td style="padding:8px 32px 24px 32px;">
                <p style="color:#cbd5e1;font-size:14px;line-height:1.6;margin:0 0 16px 0;">
                  You've been invited to join <strong style="color:#f1f5f9;">${org}</strong> on CipherScope as
                  <strong style="color:#f1f5f9;">${role}</strong>.
                </p>
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#020617;border:1px solid #1e293b;border-radius:8px;margin-bottom:24px;">
                  <tr>
                    <td style="padding:16px;font-size:13px;color:#94a3b8;">
                      <div style="margin-bottom:6px;"><span style="color:#64748b;">Invited email:</span> ${escapeHtml(input.invitedEmail)}</div>
                      <div><span style="color:#64748b;">Link expires:</span> ${expiry}</div>
                    </td>
                  </tr>
                </table>
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto 24px auto;">
                  <tr>
                    <td style="background-color:#2563eb;border-radius:8px;">
                      <a href="${input.acceptUrl}" style="display:inline-block;padding:12px 28px;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;">
                        Accept Invitation
                      </a>
                    </td>
                  </tr>
                </table>
                <p style="color:#64748b;font-size:12px;line-height:1.6;margin:0;">
                  This link is single-use and expires at the time shown above. If you weren't expecting this invitation,
                  you can safely ignore this email — no account will be created unless the link is used.
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;

  const text = [
    `You've been invited to join ${input.organizationName} on CipherScope as ${input.roleName}.`,
    ``,
    `Invited email: ${input.invitedEmail}`,
    `Link expires: ${expiry}`,
    ``,
    `Accept your invitation: ${input.acceptUrl}`,
    ``,
    `This link is single-use and expires at the time shown above. If you weren't expecting this invitation, you can safely ignore this email.`,
  ].join('\n');

  return { subject, html, text };
}
