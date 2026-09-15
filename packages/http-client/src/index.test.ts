import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpClient, isPrivateIp } from '../src/index';
import dns from 'dns';
import http from 'http';

describe('HttpClient Circuit Breaker', () => {
  it('should open circuit after threshold', async () => {
    const client = new HttpClient('test-client', {
      circuitBreakerOptions: {
        errorThresholdPercentage: 1, // open immediately on error
        resetTimeout: 1000,
      }
    });

    // Mock axios instance to throw
    (client as any).axiosInstance.request = vi.fn().mockRejectedValue(new Error('Network Error'));

    // First request fails
    await expect(client.get('/test')).rejects.toThrow('Network Error');
    
    // Circuit should be open, next request fails fast with Opossum error
    await expect(client.get('/test')).rejects.toThrow('Breaker is open');
  });
});

describe('SSRF Protection - isPrivateIp', () => {
  it('should block IPv4 loopback, link-local, and private ranges', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('127.1.2.3')).toBe(true);
    expect(isPrivateIp('169.254.169.254')).toBe(true);
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.255')).toBe(true);
    expect(isPrivateIp('192.168.1.1')).toBe(true);
    expect(isPrivateIp('0.0.0.0')).toBe(true);
  });

  it('should block IPv6 loopback, ULA, and link-local', () => {
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('::')).toBe(true);
    expect(isPrivateIp('fe80::1')).toBe(true);
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fd00::1')).toBe(true);
  });

  it('should block IPv4-mapped IPv6', () => {
    expect(isPrivateIp('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIp('::ffff:7f00:1')).toBe(true); // 127.0.0.1
    expect(isPrivateIp('::ffff:169.254.169.254')).toBe(true);
  });

  it('should allow public IPs', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
    expect(isPrivateIp('2606:4700:4700::1111')).toBe(false);
  });
});

describe('HttpClient SSRF Protection Integration', () => {
  let lookupSpy: any;

  beforeEach(() => {
    lookupSpy = vi.spyOn(dns, 'lookup');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should block requests to localhost hostname via DNS rebinding', async () => {
    // dns.lookup mock returning loopback
    lookupSpy.mockImplementation((hostname: string, options: any, callback: any) => {
      callback(null, [{ address: '127.0.0.1', family: 4 }]);
    });

    const client = new HttpClient('test-client');
    await expect(client.get('http://safedomain.com')).rejects.toThrow(/SSRF attempt blocked: Resolved to an internal IP address/);
  });

  it('should block requests to cloud metadata ip directly', async () => {
    lookupSpy.mockImplementation((hostname: string, options: any, callback: any) => {
      callback(null, [{ address: '169.254.169.254', family: 4 }]);
    });

    const client = new HttpClient('test-client');
    await expect(client.get('http://169.254.169.254')).rejects.toThrow(/SSRF attempt blocked: Resolved to an internal IP address/);
  });

  it('should block unsupported protocols', async () => {
    const client = new HttpClient('test-client');
    await expect(client.get('file:///etc/passwd')).rejects.toThrow(/SSRF attempt blocked: Unsupported protocol/);
    await expect(client.get('ftp://example.com')).rejects.toThrow(/SSRF attempt blocked: Unsupported protocol/);
  });

  it('should block URLs with embedded credentials', async () => {
    const client = new HttpClient('test-client');
    await expect(client.get('http://admin:password@example.com')).rejects.toThrow(/SSRF attempt blocked: Embedded credentials in URL are not allowed/);
  });

  it('should prevent config overrides for httpAgent and transport', async () => {
    lookupSpy.mockImplementation((hostname: string, options: any, callback: any) => {
      callback(null, [{ address: '127.0.0.1', family: 4 }]);
    });
    
    const client = new HttpClient('test-client');
    // Try to pass a fresh httpAgent that doesn't have the safeLookup function, which should bypass SSRF.
    // The request method should strip it and use the instance's secure agent instead, thus throwing.
    await expect(client.get('http://safedomain.com', { httpAgent: new http.Agent() })).rejects.toThrow(/SSRF attempt blocked: Resolved to an internal IP address/);
  });
  
  it('should validate redirect URLs and block private IPs in beforeRedirect', () => {
    const client = new HttpClient('test-client');
    const axiosInstance = (client as any).axiosInstance;
    const beforeRedirect = axiosInstance.defaults.beforeRedirect;
    
    expect(beforeRedirect).toBeDefined();
    
    // Simulate a redirect to 127.0.0.1
    expect(() => {
      beforeRedirect({
        protocol: 'http:',
        hostname: '127.0.0.1',
        path: '/'
      });
    }).toThrow(/SSRF attempt blocked: Resolved to an internal IP address/);

    // Simulate a redirect to localhost
    expect(() => {
      beforeRedirect({
        protocol: 'http:',
        hostname: 'localhost',
        path: '/secret'
      });
    }).not.toThrow(); // Because validateUrl doesn't resolve DNS, safeLookup will catch 'localhost' during connection.
    
    // Simulate a redirect to file://
    expect(() => {
      beforeRedirect({
        protocol: 'file:',
        hostname: '',
        path: '/etc/passwd'
      });
    }).toThrow(/SSRF attempt blocked: Unsupported protocol/);
  });
});
