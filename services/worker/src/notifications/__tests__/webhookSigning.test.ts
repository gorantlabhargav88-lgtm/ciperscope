import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { signWebhookPayload, verifyWebhookSignature } from '../webhookSigning';

describe('signWebhookPayload / verifyWebhookSignature', () => {
  const payload = JSON.stringify({ eventType: 'THREAT_ANALYSIS_COMPLETED', eventId: 'abc-123', threatScore: 40 });
  const secret = 'a-very-secret-webhook-secret';

  it('produces a deterministic sha256= prefixed signature', () => {
    const sig = signWebhookPayload(payload, secret);
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);

    const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
    expect(sig).toBe(expected);
  });

  it('is deterministic — same payload and secret always produce the same signature', () => {
    expect(signWebhookPayload(payload, secret)).toBe(signWebhookPayload(payload, secret));
  });

  it('changes if the payload changes by even one byte', () => {
    const sig1 = signWebhookPayload(payload, secret);
    const sig2 = signWebhookPayload(payload + ' ', secret);
    expect(sig1).not.toBe(sig2);
  });

  it('changes if the secret changes', () => {
    const sig1 = signWebhookPayload(payload, secret);
    const sig2 = signWebhookPayload(payload, secret + 'x');
    expect(sig1).not.toBe(sig2);
  });

  it('verifyWebhookSignature accepts a correct signature', () => {
    const sig = signWebhookPayload(payload, secret);
    expect(verifyWebhookSignature(payload, secret, sig)).toBe(true);
  });

  it('verifyWebhookSignature rejects a tampered payload', () => {
    const sig = signWebhookPayload(payload, secret);
    expect(verifyWebhookSignature(payload + 'tampered', secret, sig)).toBe(false);
  });

  it('verifyWebhookSignature rejects a wrong secret', () => {
    const sig = signWebhookPayload(payload, secret);
    expect(verifyWebhookSignature(payload, 'wrong-secret', sig)).toBe(false);
  });

  it('verifyWebhookSignature rejects a malformed signature header without throwing', () => {
    expect(verifyWebhookSignature(payload, secret, 'not-a-real-signature')).toBe(false);
  });
});
