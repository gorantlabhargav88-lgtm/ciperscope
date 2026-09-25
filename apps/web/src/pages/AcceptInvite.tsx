import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Shield, Loader2, WifiOff, CheckCircle2 } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import { classifyApiError } from '../lib/apiErrorState';

/**
 * Public invitation-acceptance page — GET/POST /invitations/:token(/accept)
 * (services/api/src/modules/invitation/invitation.routes.ts). No auth
 * required to view; accepting for an email that already has an account
 * requires being logged in as that exact user (enforced server-side).
 */
export const AcceptInvite = () => {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [accepted, setAccepted] = useState(false);

  const { data: preview, isLoading, error } = useQuery({
    queryKey: ['invitation-preview', token],
    queryFn: () => apiClient.getInvitationPreview(token!),
    enabled: Boolean(token),
    retry: false,
  });

  const acceptMutation = useMutation({
    mutationFn: () => apiClient.acceptInvitation(token!, { password: password || undefined, firstName: firstName || undefined, lastName: lastName || undefined }),
    onSuccess: () => setAccepted(true),
  });

  const classified = error ? classifyApiError(error, 'invitation') : null;
  const passwordsMismatch = preview?.requiresPassword && password.length > 0 && password !== confirmPassword;
  const canSubmit = preview && (!preview.requiresPassword || (password.length >= 12 && password === confirmPassword));

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
      <div className="max-w-md w-full p-8 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl">
        <div className="flex flex-col items-center mb-8">
          <Shield className="w-12 h-12 text-blue-500 mb-4" />
          <h1 className="text-2xl font-semibold text-slate-100">CiperScope</h1>
          <p className="text-slate-400 mt-2 text-sm">Organization Invitation</p>
        </div>

        {isLoading ? (
          <div className="flex justify-center py-8">
            <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
          </div>
        ) : accepted ? (
          <div className="text-center space-y-4">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
            <p className="text-slate-200">You've joined the organization.</p>
            <button
              onClick={() => navigate('/login')}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Go to sign in
            </button>
          </div>
        ) : classified || !preview ? (
          <div
            role="alert"
            className={`p-4 rounded-lg text-sm text-center flex items-center justify-center gap-2 ${classified?.kind === 'network' ? 'bg-amber-900/50 border border-amber-500/50 text-amber-200' : 'bg-red-900/50 border border-red-500/50 text-red-200'}`}
          >
            {classified?.kind === 'network' && <WifiOff className="w-4 h-4 shrink-0" aria-hidden="true" />}
            <span>{classified?.message ?? 'This invitation link is invalid or has expired.'}</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm">
              <p className="text-slate-300">You've been invited to join</p>
              <p className="text-slate-100 font-medium">{preview.organizationName}</p>
              <p className="text-slate-500 text-xs mt-1">as {preview.roleName} · {preview.email}</p>
            </div>

            {preview.requiresPassword ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">First name</label>
                    <input type="text" value={firstName} onChange={(e) => setFirstName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">Last name</label>
                    <input type="text" value={lastName} onChange={(e) => setLastName(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500" />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Create a password</label>
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500" placeholder="At least 12 characters" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Confirm password</label>
                  <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500" />
                  {passwordsMismatch && <p className="text-xs text-red-400 mt-1">Passwords don't match.</p>}
                </div>
              </>
            ) : (
              <div className="text-sm text-slate-400 bg-slate-950 border border-slate-800 rounded-lg p-3">
                An account already exists for {preview.email}.{' '}
                <Link to="/login" className="text-blue-400 hover:text-blue-300">Log in</Link> as that user, then return to this link to accept.
              </div>
            )}

            {acceptMutation.isError && (
              <div className="text-sm text-red-400 bg-red-950/30 border border-red-900/50 rounded-lg p-3 text-center">
                {classifyApiError(acceptMutation.error, 'invitation').message}
              </div>
            )}

            {preview.requiresPassword && (
              <button
                onClick={() => acceptMutation.mutate()}
                disabled={!canSubmit || acceptMutation.isPending}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {acceptMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Accept &amp; Create Account
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
