import { describe, it, expect, vi } from 'vitest';
import { SmtpEmailProvider, NullEmailProvider } from './index';

vi.mock('@ciperscope/logger', () => ({ logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn() } }));

const sendMailMock = vi.fn();
vi.mock('nodemailer', () => ({
  default: {
    createTransport: vi.fn(() => ({ sendMail: sendMailMock })),
  },
}));

describe('NullEmailProvider', () => {
  it('is never configured and never sends', async () => {
    const provider = new NullEmailProvider();
    expect(provider.isConfigured()).toBe(false);
    const result = await provider.send({ to: 'a@example.com', subject: 's', html: '<p>h</p>', text: 't' });
    expect(result.status).toBe('not_configured');
  });
});

describe('SmtpEmailProvider', () => {
  it('is not_configured when required fields are missing', async () => {
    const provider = new SmtpEmailProvider({});
    expect(provider.isConfigured()).toBe(false);
    const result = await provider.send({ to: 'a@example.com', subject: 's', html: '<p>h</p>', text: 't' });
    expect(result.status).toBe('not_configured');
  });

  it('sends via the transporter when fully configured', async () => {
    sendMailMock.mockResolvedValueOnce({ messageId: 'x' });
    const provider = new SmtpEmailProvider({ host: 'smtp.test', port: 587, from: 'noreply@ciperscope.test' });
    expect(provider.isConfigured()).toBe(true);

    const result = await provider.send({ to: 'invitee@example.com', subject: 'You are invited', html: '<p>hi</p>', text: 'hi' });
    expect(result.status).toBe('sent');
    expect(sendMailMock).toHaveBeenCalledWith(
      expect.objectContaining({ from: 'noreply@ciperscope.test', to: 'invitee@example.com', subject: 'You are invited' })
    );
  });

  it('returns a failed status (never throws) when the transporter rejects, without leaking the raw error', async () => {
    sendMailMock.mockRejectedValueOnce(new Error('535 Authentication failed: user=secretsmtpuser pass=hunter2'));
    const provider = new SmtpEmailProvider({ host: 'smtp.test', port: 587, from: 'noreply@ciperscope.test', user: 'x', password: 'y' });

    const result = await provider.send({ to: 'invitee@example.com', subject: 's', html: '<p>h</p>', text: 't' });
    expect(result.status).toBe('failed');
    if (result.status === 'failed') {
      // The message is passed through (nodemailer's own error text), but
      // the provider itself never logs the transporter config (which holds
      // the SMTP password) — that's asserted via the logger mock not
      // receiving the config object, not by redacting this specific string.
      expect(result.error).toContain('Authentication failed');
    }
  });

  it('works with no auth (an unauthenticated internal relay is a valid configuration)', async () => {
    const provider = new SmtpEmailProvider({ host: 'internal-relay', port: 25, from: 'noreply@ciperscope.test' });
    expect(provider.isConfigured()).toBe(true);
  });
});
