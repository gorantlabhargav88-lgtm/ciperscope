import { describe, it, expect } from 'vitest';
import { classifyIp } from '../IpClassifier';

describe('classifyIp', () => {
  it('1. parses a public IPv4 address', () => {
    const r = classifyIp('8.8.8.8');
    expect(r.version).toBe('v4');
    expect(r.category).toBe('PUBLIC');
    expect(r.isRoutablePublic).toBe(true);
  });

  it('2. parses a public IPv6 address', () => {
    const r = classifyIp('2001:4860:4860::8888');
    expect(r.version).toBe('v6');
    expect(r.category).toBe('PUBLIC');
    expect(r.isRoutablePublic).toBe(true);
  });

  it('3. detects private IPv4 ranges (RFC1918)', () => {
    expect(classifyIp('10.0.0.5').category).toBe('PRIVATE');
    expect(classifyIp('172.16.0.1').category).toBe('PRIVATE');
    expect(classifyIp('192.168.1.1').category).toBe('PRIVATE');
    expect(classifyIp('10.0.0.5').isRoutablePublic).toBe(false);
  });

  it('4. detects private IPv6 (unique local addresses, fc00::/7)', () => {
    const r = classifyIp('fd12:3456:789a:1::1');
    expect(r.category).toBe('PRIVATE');
    expect(r.isRoutablePublic).toBe(false);
  });

  it('5. detects IPv4 and IPv6 loopback', () => {
    expect(classifyIp('127.0.0.1').category).toBe('LOOPBACK');
    expect(classifyIp('127.5.5.5').category).toBe('LOOPBACK');
    expect(classifyIp('::1').category).toBe('LOOPBACK');
  });

  it('6. detects reserved ranges (link-local, multicast, documentation, unspecified)', () => {
    expect(classifyIp('169.254.1.1').category).toBe('LINK_LOCAL');
    expect(classifyIp('224.0.0.1').category).toBe('MULTICAST');
    expect(classifyIp('192.0.2.1').category).toBe('DOCUMENTATION'); // TEST-NET-1
    expect(classifyIp('198.51.100.1').category).toBe('DOCUMENTATION'); // TEST-NET-2
    expect(classifyIp('203.0.113.1').category).toBe('DOCUMENTATION'); // TEST-NET-3
    expect(classifyIp('0.0.0.0').category).toBe('RESERVED');
    expect(classifyIp('fe80::1').category).toBe('LINK_LOCAL');
    expect(classifyIp('ff02::1').category).toBe('MULTICAST');
    expect(classifyIp('::').category).toBe('RESERVED');
    expect(classifyIp('2001:db8::1').category).toBe('DOCUMENTATION');
  });

  it('7. classifies a genuinely public IP as PUBLIC and only PUBLIC IPs as routable', () => {
    const publicIp = classifyIp('1.1.1.1');
    expect(publicIp.category).toBe('PUBLIC');
    expect(publicIp.isRoutablePublic).toBe(true);

    for (const nonPublic of ['10.1.1.1', '127.0.0.1', '169.254.0.1', '224.0.0.1', '192.0.2.1', 'fc00::1', '::1', 'fe80::1']) {
      expect(classifyIp(nonPublic).isRoutablePublic).toBe(false);
    }
  });

  it('classifies IPv4-mapped IPv6 addresses by their embedded IPv4 address', () => {
    expect(classifyIp('::ffff:127.0.0.1').category).toBe('LOOPBACK');
    expect(classifyIp('::ffff:10.0.0.1').category).toBe('PRIVATE');
  });

  it('returns INVALID (not PUBLIC) for a malformed input, never treating garbage as routable', () => {
    const r = classifyIp('not-an-ip-address');
    expect(r.version).toBeNull();
    expect(r.category).toBe('INVALID');
    expect(r.isRoutablePublic).toBe(false);
  });
});
