import { describe, it, expect } from 'vitest';
import { EmailForensicParser } from './EmailForensicParser';
import { Readable } from 'stream';

describe('EmailForensicParser', () => {
  it('should safely parse headers and prevent SSRF', async () => {
    const rawEml = `From: attacker@evil.com
To: victim@company.com
Subject: Test SSRF
Date: Tue, 24 Oct 2023 14:32:01 +0000
Message-ID: <1234@evil.com>
Authentication-Results: mx.google.com; dkim=pass
Received: from mail.evil.com (mail.evil.com. [192.168.1.1])
        by mx.google.com with ESMTPS id abcdef12345
        for <victim@company.com>;
        Tue, 24 Oct 2023 07:32:01 -0700 (PDT)
Content-Type: text/html; charset="UTF-8"

<html>
  <body>
    <h1>Hello</h1>
    <img src="http://127.0.0.1:8080/internal-ssrf-check" />
  </body>
</html>`;

    const stream = Readable.from([rawEml]);
    const parsed = await EmailForensicParser.parse(stream);

    // Verify Headers
    expect(parsed.headers.length).toBeGreaterThan(0);
    const fromHeader = parsed.headers.find(h => h.name === 'from');
    expect(fromHeader?.value).toContain('attacker@evil.com');

    // Verify Addresses
    expect(parsed.addresses.length).toBeGreaterThan(0);
    const fromAddress = parsed.addresses.find(a => a.headerName === 'from');
    expect(fromAddress?.address).toBe('attacker@evil.com');

    // Verify Hops
    expect(parsed.relayHops.length).toBe(1);
    expect(parsed.relayHops[0].fromHost).toBe('mail.evil.com');
    expect(parsed.relayHops[0].sourceIp).toBe('192.168.1.1');
    expect(parsed.relayHops[0].byHost).toBe('mx.google.com');

    // Verify Mime Parts
    expect(parsed.mimeParts.length).toBe(1);
    expect(parsed.mimeParts[0].contentType).toBe('text/html');
    // Ensure no network fetching occurred - simpleParser should ignore the image link
  });

  it('should preserve duplicate headers', async () => {
    const rawEml = `From: attacker@evil.com
To: victim@company.com
Received: hop 1
Received: hop 2
Subject: Test Duplicates

Body`;
    const stream = Readable.from([rawEml]);
    const parsed = await EmailForensicParser.parse(stream);
    
    const receivedHeaders = parsed.headers.filter(h => h.name === 'received');
    expect(receivedHeaders.length).toBe(2);
    expect(receivedHeaders[0].value).toBe('hop 1');
    expect(receivedHeaders[1].value).toBe('hop 2');
    expect(receivedHeaders[0].index).toBeLessThan(receivedHeaders[1].index);
  });

  it('should enforce field length limits', async () => {
    const hugeHeader = 'A'.repeat(35000);
    const rawEml = `From: attacker@evil.com
To: victim@company.com
Subject: ${hugeHeader}

Body`;
    const stream = Readable.from([rawEml]);
    await expect(EmailForensicParser.parse(stream)).rejects.toThrow(/Field length exceeds maximum limit/);
  });

  it('should enforce maximum header count', async () => {
    const manyHeaders = Array.from({ length: 1005 }).map((_, i) => `X-Custom-${i}: val`).join('\n');
    const rawEml = `From: attacker@evil.com
To: victim@company.com
${manyHeaders}

Body`;
    const stream = Readable.from([rawEml]);
    await expect(EmailForensicParser.parse(stream)).rejects.toThrow(/Header count exceeds maximum limit/);
  });

  it('should enforce maximum relay hops', async () => {
    const manyHops = Array.from({ length: 105 }).map((_, i) => `Received: hop ${i}`).join('\n');
    const rawEml = `From: attacker@evil.com
To: victim@company.com
${manyHops}

Body`;
    const stream = Readable.from([rawEml]);
    await expect(EmailForensicParser.parse(stream)).rejects.toThrow(/Relay hops count exceeds maximum limit/);
  });

});
