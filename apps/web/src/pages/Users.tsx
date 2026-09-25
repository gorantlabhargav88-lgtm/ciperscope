import { useState } from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { Loader2, AlertTriangle, ShieldOff, Users as UsersIcon, Search, Plus, Copy, Check, Trash2, Mail, XCircle, RotateCw, CheckCircle2, AlertCircle } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';
import { Dialog, DialogContent } from '../components/ui/dialog';
import type { OrgMember, InvitationItem, CreatedInvitation } from '@ciperscope/types';

const EMAIL_STATUS_BADGE: Record<string, { label: string; cls: string; icon: typeof CheckCircle2 }> = {
  SENT: { label: 'Sent', cls: 'bg-security-low/10 text-security-low border-security-low/20', icon: CheckCircle2 },
  FAILED: { label: 'Delivery failed', cls: 'bg-security-critical/10 text-security-critical border-security-critical/20', icon: AlertCircle },
  NOT_CONFIGURED: { label: 'No email provider', cls: 'bg-slate-800 text-slate-500 border-slate-700', icon: AlertCircle },
};

/**
 * Organization Users & Roles — GET/POST/PATCH/DELETE /members
 * (services/api/src/modules/members/members.routes.ts). USER_READ/
 * USER_MANAGE-gated server-side; a real 403 is shown here (never bypassed)
 * when the current user lacks the required permission.
 */
export const Users = () => {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [roleId, setRoleId] = useState('');
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null]);
  const [cursorIndex, setCursorIndex] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [showInvite, setShowInvite] = useState(false);
  const [editMember, setEditMember] = useState<OrgMember | null>(null);
  const [removeMember, setRemoveMember] = useState<OrgMember | null>(null);

  const cursor = cursorStack[cursorIndex] ?? undefined;

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['members', cursor, search, roleId],
    queryFn: () => apiClient.getMembers({ cursor: cursor ?? undefined, q: search || undefined, roleId: roleId || undefined }),
    placeholderData: keepPreviousData,
  });

  const { data: rolesData } = useQuery({
    queryKey: ['member-roles'],
    queryFn: () => apiClient.getMemberRoles(),
  });

  const classified = error ? classifyApiError(error, 'organization members') : null;
  const items = data?.items ?? [];

  const resetPaging = () => { setCursorStack([null]); setCursorIndex(0); };
  const goNext = () => {
    if (!data?.nextCursor) return;
    const next = [...cursorStack.slice(0, cursorIndex + 1), data.nextCursor];
    setCursorStack(next);
    setCursorIndex(next.length - 1);
  };
  const goPrev = () => { if (cursorIndex > 0) setCursorIndex(cursorIndex - 1); };

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['members'] });

  const { data: invitationsData } = useQuery({
    queryKey: ['invitations'],
    queryFn: () => apiClient.getInvitations({ status: 'PENDING', limit: 25 }),
  });
  const invalidateInvitations = () => queryClient.invalidateQueries({ queryKey: ['invitations'] });

  const revokeInvitationMutation = useMutation({
    mutationFn: (id: string) => apiClient.revokeInvitation(id),
    onSuccess: invalidateInvitations,
  });

  const [resendResult, setResendResult] = useState<CreatedInvitation | null>(null);
  const resendInvitationMutation = useMutation({
    mutationFn: (id: string) => apiClient.resendInvitation(id),
    onSuccess: (res) => {
      invalidateInvitations();
      if (res.devOnlyInviteUrl) setResendResult(res);
    },
  });

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-2 border-b border-slate-800 pb-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <UsersIcon className="w-8 h-8 text-blue-500" />
            <h1 className="text-3xl font-bold text-white tracking-tight">Users &amp; Roles</h1>
          </div>
          <p className="text-slate-400 mt-2">Manage who has access to this organization and what they can do.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowInvite(true)}
            className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Mail className="w-4 h-4" /> Invite Member
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
          >
            <Plus className="w-4 h-4" /> Add Member
          </button>
        </div>
      </header>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); resetPaging(); }}
            placeholder="Search name or email..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-600"
          />
        </div>
        <select
          value={roleId}
          onChange={(e) => { setRoleId(e.target.value); resetPaging(); }}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-600"
        >
          <option value="">All roles</option>
          {rolesData?.roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : classified ? (
        <div className={`border p-6 rounded-xl flex items-center gap-4 ${classified.kind === 'unauthorized' || classified.kind === 'forbidden' ? 'bg-amber-950/30 border-amber-900/50' : 'bg-red-950/30 border-red-900/50'}`}>
          {classified.kind === 'forbidden' ? <ShieldOff className="w-8 h-8 text-amber-500" /> : <AlertTriangle className="w-8 h-8 text-red-500" />}
          <div>
            <h3 className="font-medium text-slate-100">{classified.kind === 'forbidden' ? 'Access denied' : 'Failed to load members'}</h3>
            <p className="text-sm text-slate-400">{classified.message}</p>
          </div>
        </div>
      ) : items.length === 0 ? (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          No members match these filters.
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4 font-medium">Name / Email</th>
                  <th className="px-6 py-4 font-medium">Role</th>
                  <th className="px-6 py-4 font-medium">Status</th>
                  <th className="px-6 py-4 font-medium">Joined</th>
                  <th className="px-6 py-4 font-medium">Last Activity</th>
                  <th className="px-6 py-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {items.map((m) => (
                  <tr key={m.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-3">
                      <div className="text-slate-200">{`${m.firstName ?? ''} ${m.lastName ?? ''}`.trim() || '—'}</div>
                      <div className="text-xs text-slate-500">{m.email}</div>
                    </td>
                    <td className="px-6 py-3">
                      <span className="px-2 py-0.5 rounded text-xs font-medium border bg-slate-800 text-slate-300 border-slate-700">{m.role.name}</span>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${m.isActive ? 'bg-security-low/10 text-security-low border-security-low/20' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                        {m.isActive ? 'Active' : 'Deactivated'}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-slate-400 whitespace-nowrap">{new Date(m.joinedAt).toLocaleDateString()}</td>
                    <td className="px-6 py-3 text-slate-400 whitespace-nowrap">{m.lastLoginAt ? new Date(m.lastLoginAt).toLocaleString() : 'Never logged in'}</td>
                    <td className="px-6 py-3 text-right">
                      <button onClick={() => setEditMember(m)} className="text-xs text-blue-400 hover:text-blue-300 mr-3">Edit</button>
                      <button onClick={() => setRemoveMember(m)} className="text-xs text-rose-400 hover:text-rose-300">Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 text-xs text-slate-400">
            <span>{items.length} member{items.length !== 1 ? 's' : ''} on this page{isFetching && <Loader2 className="inline w-3 h-3 ml-2 animate-spin" />}</span>
            <div className="flex gap-2">
              <button onClick={goPrev} disabled={cursorIndex === 0} className="px-3 py-1.5 rounded border border-slate-800 bg-slate-950 disabled:opacity-40 hover:border-blue-600 transition-colors">Previous</button>
              <button onClick={goNext} disabled={!data?.nextCursor} className="px-3 py-1.5 rounded border border-slate-800 bg-slate-950 disabled:opacity-40 hover:border-blue-600 transition-colors">Next</button>
            </div>
          </div>
        </div>
      )}

      {invitationsData && invitationsData.items.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="px-4 py-3 border-b border-slate-800">
            <h2 className="text-sm font-medium text-slate-200">Pending Invitations</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3 font-medium">Email</th>
                  <th className="px-6 py-3 font-medium">Role</th>
                  <th className="px-6 py-3 font-medium">Delivery</th>
                  <th className="px-6 py-3 font-medium">Expires</th>
                  <th className="px-6 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {invitationsData.items.map((inv: InvitationItem) => {
                  const badge = EMAIL_STATUS_BADGE[inv.emailStatus] ?? EMAIL_STATUS_BADGE.NOT_CONFIGURED;
                  const BadgeIcon = badge.icon;
                  const isResendingThis = resendInvitationMutation.isPending && resendInvitationMutation.variables === inv.id;
                  return (
                    <tr key={inv.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-3">{inv.email}</td>
                      <td className="px-6 py-3">
                        <span className="px-2 py-0.5 rounded text-xs font-medium border bg-slate-800 text-slate-300 border-slate-700">{inv.role.name}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium border inline-flex items-center gap-1 ${badge.cls}`}
                          title={inv.emailStatus === 'FAILED' ? (inv.emailError ?? undefined) : undefined}
                        >
                          <BadgeIcon className="w-3 h-3" /> {badge.label}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-slate-400">{new Date(inv.expiresAt).toLocaleDateString()}</td>
                      <td className="px-6 py-3 text-right">
                        <button
                          onClick={() => resendInvitationMutation.mutate(inv.id)}
                          disabled={resendInvitationMutation.isPending}
                          className="text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 disabled:opacity-40 mr-3"
                        >
                          {isResendingThis ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCw className="w-3.5 h-3.5" />}
                          {isResendingThis ? 'Sending…' : 'Resend'}
                        </button>
                        <button
                          onClick={() => revokeInvitationMutation.mutate(inv.id)}
                          disabled={revokeInvitationMutation.isPending}
                          className="text-xs text-rose-400 hover:text-rose-300 inline-flex items-center gap-1 disabled:opacity-40"
                        >
                          <XCircle className="w-3.5 h-3.5" /> Revoke
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {resendResult?.devOnlyInviteUrl && (
        <Dialog open onOpenChange={(open) => !open && setResendResult(null)}>
          <DialogContent className="p-6 space-y-4">
            <h2 className="text-lg font-semibold text-slate-100">Invitation resent</h2>
            <p className="text-sm text-amber-400 bg-amber-950/20 border border-amber-900/40 rounded p-3">
              No email service is configured in this deployment. Share this new link with {resendResult.email} directly — the previous link no longer works.
            </p>
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded p-3">
              <code className="flex-1 text-xs text-emerald-400 break-all">{resendResult.devOnlyInviteUrl}</code>
              <button
                onClick={() => navigator.clipboard.writeText(resendResult.devOnlyInviteUrl!)}
                className="text-slate-400 hover:text-slate-200 shrink-0"
                aria-label="Copy invite link"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
            <div className="flex justify-end">
              <button onClick={() => setResendResult(null)} className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white">Done</button>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {showAdd && <AddMemberDialog roles={rolesData?.roles ?? []} onClose={() => setShowAdd(false)} onAdded={invalidate} />}
      {showInvite && <InviteMemberDialog roles={rolesData?.roles ?? []} onClose={() => setShowInvite(false)} onInvited={invalidateInvitations} />}
      {editMember && <EditMemberDialog member={editMember} roles={rolesData?.roles ?? []} onClose={() => setEditMember(null)} onSaved={invalidate} />}
      {removeMember && <RemoveMemberDialog member={removeMember} onClose={() => setRemoveMember(null)} onRemoved={invalidate} />}
    </div>
  );
};

function InviteMemberDialog({ roles, onClose, onInvited }: { roles: { id: string; name: string }[]; onClose: () => void; onInvited: () => void }) {
  const [email, setEmail] = useState('');
  const [selectedRoleId, setSelectedRoleId] = useState(roles[0]?.id ?? '');
  const [result, setResult] = useState<CreatedInvitation | null>(null);
  const [copied, setCopied] = useState(false);

  const mutation = useMutation({
    mutationFn: () => apiClient.createInvitation({ email, roleId: selectedRoleId }),
    onSuccess: (res) => {
      onInvited();
      setResult(res);
    },
  });

  if (result) {
    return (
      <Dialog open onOpenChange={(open) => !open && onClose()}>
        <DialogContent className="p-6 space-y-4">
          <h2 className="text-lg font-semibold text-slate-100">Invitation created</h2>

          {result.emailStatus === 'SENT' && (
            <p className="text-sm text-emerald-400 bg-emerald-950/20 border border-emerald-900/40 rounded p-3 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" /> Invitation email sent to {result.email}.
            </p>
          )}
          {result.emailStatus === 'FAILED' && (
            <p className="text-sm text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-3 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                The invitation was created, but the email failed to send{result.emailError ? `: ${result.emailError}` : '.'} Use Resend from the
                pending invitations list to try again once the issue is resolved.
              </span>
            </p>
          )}
          {result.emailStatus === 'NOT_CONFIGURED' && !result.devOnlyInviteUrl && (
            <p className="text-sm text-amber-400 bg-amber-950/20 border border-amber-900/40 rounded p-3">
              No email service is configured in this deployment. Share the invitation link with {result.email} through another channel — an
              administrator can retrieve it once SMTP is configured and the invitation is resent.
            </p>
          )}

          {result.devOnlyInviteUrl && (
            <>
              <p className="text-sm text-amber-400 bg-amber-950/20 border border-amber-900/40 rounded p-3">
                No email service is configured in this deployment. This link is shown here only because this is a non-production environment — share it with {email} directly.
              </p>
              <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded p-3">
                <code className="flex-1 text-xs text-emerald-400 break-all">{result.devOnlyInviteUrl}</code>
                <button
                  onClick={() => { navigator.clipboard.writeText(result.devOnlyInviteUrl!); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                  className="text-slate-400 hover:text-slate-200 shrink-0"
                  aria-label="Copy invite link"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </>
          )}

          <div className="flex justify-end">
            <button onClick={onClose} className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white">Done</button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="p-6 space-y-4">
        <h2 className="text-lg font-semibold text-slate-100">Invite Member</h2>
        <p className="text-xs text-slate-500">
          The invitee sets their own password when accepting — unlike "Add Member," no temporary password is generated for them.
        </p>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200" placeholder="analyst@organization.com" />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Role</label>
            <select value={selectedRoleId} onChange={(e) => setSelectedRoleId(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200">
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </div>
        </div>
        {mutation.isError && (
          <div className="text-xs text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-2">
            {classifyApiError(mutation.error, 'invitation').message}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="text-sm px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={!email || !selectedRoleId || mutation.isPending}
            className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 flex items-center gap-1.5"
          >
            {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Send Invitation
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function AddMemberDialog({ roles, onClose, onAdded }: { roles: { id: string; name: string }[]; onClose: () => void; onAdded: () => void }) {
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [selectedRoleId, setSelectedRoleId] = useState(roles[0]?.id ?? '');
  const [tempPassword, setTempPassword] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const mutation = useMutation({
    mutationFn: () => apiClient.createMember({ email, firstName: firstName || undefined, lastName: lastName || undefined, roleId: selectedRoleId }),
    onSuccess: (res) => {
      onAdded();
      if (res.temporaryPassword) setTempPassword(res.temporaryPassword);
      else onClose();
    },
  });

  if (tempPassword) {
    return (
      <Dialog open onOpenChange={(open) => !open && onClose()}>
        <DialogContent className="p-6 space-y-4">
          <h2 className="text-lg font-semibold text-slate-100">Member added</h2>
          <p className="text-sm text-slate-400">
            A new account was created for <span className="text-slate-200">{email}</span>. This temporary password is shown once — it cannot be retrieved again.
          </p>
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded p-3">
            <code className="flex-1 text-sm text-emerald-400 break-all">{tempPassword}</code>
            <button
              onClick={() => { navigator.clipboard.writeText(tempPassword); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
              className="text-slate-400 hover:text-slate-200"
              aria-label="Copy temporary password"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <div className="flex justify-end">
            <button onClick={onClose} className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white">Done</button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="p-6 space-y-4">
        <h2 className="text-lg font-semibold text-slate-100">Add Member</h2>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200" placeholder="analyst@organization.com" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-400 block mb-1">First name</label>
              <input type="text" value={firstName} onChange={(e) => setFirstName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200" />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Last name</label>
              <input type="text" value={lastName} onChange={(e) => setLastName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200" />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Role</label>
            <select value={selectedRoleId} onChange={(e) => setSelectedRoleId(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200">
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </div>
        </div>
        {mutation.isError && (
          <div className="text-xs text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-2">
            {classifyApiError(mutation.error, 'member').message}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="text-sm px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={!email || !selectedRoleId || mutation.isPending}
            className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 flex items-center gap-1.5"
          >
            {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Add Member
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function EditMemberDialog({ member, roles, onClose, onSaved }: { member: OrgMember; roles: { id: string; name: string }[]; onClose: () => void; onSaved: () => void }) {
  const [roleId, setRoleId] = useState(member.role.id);
  const [isActive, setIsActive] = useState(member.isActive);

  const mutation = useMutation({
    mutationFn: () => apiClient.updateMember(member.id, {
      ...(roleId !== member.role.id ? { roleId } : {}),
      ...(isActive !== member.isActive ? { isActive } : {}),
    }),
    onSuccess: () => { onSaved(); onClose(); },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="p-6 space-y-4">
        <h2 className="text-lg font-semibold text-slate-100">Edit Member</h2>
        <p className="text-sm text-slate-400">{member.email}</p>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Role</label>
            <select value={roleId} onChange={(e) => setRoleId(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200">
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </div>
          <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded px-3 py-2">
            <div>
              <div className="text-sm text-slate-200">Account active</div>
              <div className="text-xs text-slate-500">This toggles the account everywhere, not just this organization.</div>
            </div>
            <button
              role="switch"
              aria-checked={isActive}
              aria-label="Toggle account active"
              onClick={() => setIsActive((v) => !v)}
              className={`w-10 h-6 rounded-full transition-colors relative shrink-0 ${isActive ? 'bg-emerald-600' : 'bg-slate-700'}`}
            >
              <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${isActive ? 'translate-x-5' : 'translate-x-1'}`} />
            </button>
          </div>
        </div>
        {mutation.isError && (
          <div className="text-xs text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-2">
            {classifyApiError(mutation.error, 'member').message}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="text-sm px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || (roleId === member.role.id && isActive === member.isActive)}
            className="text-sm px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 flex items-center gap-1.5"
          >
            {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Save
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RemoveMemberDialog({ member, onClose, onRemoved }: { member: OrgMember; onClose: () => void; onRemoved: () => void }) {
  const mutation = useMutation({
    mutationFn: () => apiClient.removeMember(member.id),
    onSuccess: () => { onRemoved(); onClose(); },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-rose-950/40 flex items-center justify-center shrink-0">
            <Trash2 className="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Remove member</h2>
            <p className="text-sm text-slate-400">This removes {member.email} from this organization. This cannot be undone.</p>
          </div>
        </div>
        {mutation.isError && (
          <div className="text-xs text-rose-400 bg-rose-950/20 border border-rose-900/40 rounded p-2">
            {classifyApiError(mutation.error, 'member').message}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="text-sm px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="text-sm px-4 py-2 rounded bg-rose-600 hover:bg-rose-500 text-white disabled:opacity-40 flex items-center gap-1.5"
          >
            {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Remove
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
