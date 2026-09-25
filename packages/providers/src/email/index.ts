import nodemailer, { Transporter } from 'nodemailer';
import { logger } from '@ciperscope/logger';

export interface SendEmailInput {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export type EmailSendResult =
  | { status: 'sent' }
  | { status: 'not_configured' }
  | { status: 'failed'; error: string };

export interface EmailProvider {
  readonly name: string;
  isConfigured(): boolean;
  send(input: SendEmailInput): Promise<EmailSendResult>;
}

/**
 * Generic SMTP delivery — works with any real provider (Postmark, SES SMTP
 * endpoint, SendGrid SMTP, Mailgun SMTP, a self-hosted relay, ...) without
 * hardcoding one, matching the same provider-abstraction pattern already
 * used for threat intelligence (packages/providers/src/cti) and geo lookup
 * (services/worker/src/cti/providers). Configured entirely from env vars
 * via @ciperscope/config — never hardcoded, never exposed to the frontend.
 */
export class SmtpEmailProvider implements EmailProvider {
  public readonly name = 'SMTP';
  private transporter: Transporter | null = null;
  private readonly fromAddress: string | undefined;

  constructor(config: {
    host?: string;
    port?: number;
    user?: string;
    password?: string;
    from?: string;
    secure?: boolean;
  }) {
    this.fromAddress = config.from;
    if (config.host && config.port && config.from) {
      this.transporter = nodemailer.createTransport({
        host: config.host,
        port: config.port,
        secure: config.secure ?? config.port === 465,
        // auth is optional — some internal relays (e.g. a local Postfix
        // relay, or a provider's IP-allowlisted SMTP endpoint) require no
        // credentials at all.
        auth: config.user && config.password ? { user: config.user, pass: config.password } : undefined,
      });
    }
  }

  isConfigured(): boolean {
    return this.transporter !== null;
  }

  async send(input: SendEmailInput): Promise<EmailSendResult> {
    if (!this.transporter || !this.fromAddress) {
      return { status: 'not_configured' };
    }
    try {
      await this.transporter.sendMail({
        from: this.fromAddress,
        to: input.to,
        subject: input.subject,
        html: input.html,
        text: input.text,
      });
      return { status: 'sent' };
    } catch (err) {
      // Never log the transporter config (carries the SMTP password) or
      // the full error object (nodemailer errors can embed the auth
      // command) — only a safe, human-readable message.
      const message = err instanceof Error ? err.message : 'Unknown SMTP error';
      logger.warn({ recipientDomain: input.to.split('@')[1], message }, 'Email delivery failed');
      return { status: 'failed', error: message };
    }
  }
}

/** Always available, never sends anything — the honest degraded mode when no SMTP_* env vars are set. */
export class NullEmailProvider implements EmailProvider {
  public readonly name = 'Null';
  isConfigured(): boolean {
    return false;
  }
  async send(): Promise<EmailSendResult> {
    return { status: 'not_configured' };
  }
}
