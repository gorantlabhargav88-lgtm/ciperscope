import { env } from '@ciperscope/config';
import { EmailProvider, SmtpEmailProvider, NullEmailProvider } from '@ciperscope/providers';

/**
 * Same dependency-injection pattern as services/worker/src/cti/CtiConfig.ts's
 * getGeoProvider(): read credentials from the existing @ciperscope/config
 * env schema and inject them into the provider, rather than having the
 * provider read process.env itself — keeps packages/providers free of a
 * dependency on @ciperscope/config and matches the established convention.
 */
export function getEmailProvider(): EmailProvider {
  if (env.SMTP_HOST && env.SMTP_PORT && env.SMTP_FROM) {
    return new SmtpEmailProvider({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      user: env.SMTP_USER,
      password: env.SMTP_PASSWORD,
      from: env.SMTP_FROM,
      secure: env.SMTP_SECURE === 'true',
    });
  }
  return new NullEmailProvider();
}
