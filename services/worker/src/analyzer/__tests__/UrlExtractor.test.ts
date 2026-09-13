import { describe, it, expect } from 'vitest';
import { UrlExtractor } from '../UrlExtractor';

describe('UrlExtractor', () => {
  it('extracts and normalizes http/https URLs from text', () => {
    const text = 'Check out this link: https://example.com/login and http://test.com';
    const urls = UrlExtractor.extractFromText(text);
    
    expect(urls).toHaveLength(2);
    expect(urls[0].originalObservedUrl).toBe('https://example.com/login');
    expect(urls[0].normalizedUrl).toBe('https://example.com/login');
    expect(urls[0].source).toBe('TEXT');
    
    expect(urls[1].originalObservedUrl).toBe('http://test.com');
  });

  it('rejects dangerous schemes', () => {
    const text = 'Here is a file: file:///etc/passwd and a script: javascript:alert(1)';
    const urls = UrlExtractor.extractFromText(text);
    // Regex in text extraction only looks for http/https currently, so these shouldn't even be matched by regex
    expect(urls).toHaveLength(0);
  });

  it('extracts URLs from HTML safely', () => {
    const html = `
      <html>
        <body>
          <a href="https://example.com/link">Link</a>
          <img src="http://example.com/image.png" />
          <form action="https://example.com/submit"></form>
          <a href="javascript:alert(1)">XSS</a>
          <a href="file:///etc/passwd">LFI</a>
        </body>
      </html>
    `;
    const urls = UrlExtractor.extractFromHtml(html);
    
    expect(urls).toHaveLength(3);
    
    const href = urls.find(u => u.source === 'HTML_HREF');
    expect(href?.originalObservedUrl).toBe('https://example.com/link');
    
    const src = urls.find(u => u.source === 'HTML_SRC');
    expect(src?.originalObservedUrl).toBe('http://example.com/image.png');
    
    const action = urls.find(u => u.source === 'HTML_ACTION');
    expect(action?.originalObservedUrl).toBe('https://example.com/submit');
  });

  it('detects URL indicators and obfuscation', () => {
    const html = `<a href="https://xn--80ak6aa92e.com/%20admin">Punycode and Percent</a>`;
    const urls = UrlExtractor.extractFromHtml(html);
    
    expect(urls).toHaveLength(1);
    expect(urls[0].isObfuscated).toBe(true);
    expect(urls[0].indicators).toContain('PERCENT_ENCODING');
    expect(urls[0].indicators).toContain('PUNYCODE');
  });

  it('detects IP literals', () => {
    const urls = UrlExtractor.extractFromText('http://192.168.1.1/admin');
    expect(urls).toHaveLength(1);
    expect(urls[0].indicators).toContain('IP_LITERAL');
    expect(urls[0].indicators).toContain('PRIVATE_IP_LITERAL');
  });
});
