import crypto from 'crypto';

/**
 * HMAC-SHA256 signature for an outbound webhook payload, so a receiver can
 * verify the request actually came from CipherScope and wasn't tampered
 * with in transit. Signs the EXACT bytes being transmitted — callers must
 * pass the same string used as the HTTP request body, never re-derive it.
 */
export function signWebhookPayload(payloadJson: string, secret: string): string {
  const digest = crypto.createHmac('sha256', secret).update(payloadJson, 'utf8').digest('hex');
  return `sha256=${digest}`;
}

/** Constant-time comparison, for receivers/tests verifying a signature. */
export function verifyWebhookSignature(payloadJson: string, secret: string, signatureHeader: string): boolean {
  const expected = signWebhookPayload(payloadJson, secret);
  const expectedBuf = Buffer.from(expected);
  const actualBuf = Buffer.from(signatureHeader);
  if (expectedBuf.length !== actualBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}
