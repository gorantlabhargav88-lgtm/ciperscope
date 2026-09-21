import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  canonicalizeHeaderSimple,
  canonicalizeHeaderRelaxed,
  canonicalizeBodySimple,
  canonicalizeBodyRelaxed
} from '../canonicalize';
import { RawHeader } from '../rawMessage';

describe('DKIM canonicalization (RFC 6376 §3.4)', () => {
  describe('header canonicalization', () => {
    const header: RawHeader = { name: 'Subject', value: '  Is dinner ready?  ', raw: 'Subject:  Is dinner ready?  ' };

    it('simple: leaves the header completely unchanged, only appending CRLF', () => {
      expect(canonicalizeHeaderSimple(header)).toBe('Subject:  Is dinner ready?  \r\n');
    });

    it('relaxed: lowercases the name, trims/collapses the value, no space after colon', () => {
      expect(canonicalizeHeaderRelaxed(header)).toBe('subject:Is dinner ready?\r\n');
    });

    it('relaxed: unfolds continuation lines and collapses the resulting whitespace to a single space', () => {
      const folded: RawHeader = {
        name: 'B',
        value: ' Y\t\r\n\tZ  ',
        raw: 'B: Y\t\r\n\tZ  '
      };
      expect(canonicalizeHeaderRelaxed(folded)).toBe('b:Y Z\r\n');
    });

    it('relaxed: trims whitespace around the header name itself', () => {
      const spaced: RawHeader = { name: ' A ', value: ' X', raw: ' A : X' };
      expect(canonicalizeHeaderRelaxed(spaced)).toBe('a:X\r\n');
    });
  });

  describe('body canonicalization', () => {
    it('simple: strips trailing blank lines but keeps exactly one trailing CRLF', () => {
      const body = Buffer.from('Hi.\r\n\r\n\r\n', 'latin1');
      expect(canonicalizeBodySimple(body).toString('latin1')).toBe('Hi.\r\n');
    });

    it('simple: an empty body canonicalizes to a single CRLF (matches RFC 6376\'s own example hash)', () => {
      const canonical = canonicalizeBodySimple(Buffer.alloc(0));
      const hash = crypto.createHash('sha256').update(canonical).digest('base64');
      expect(canonical.toString('latin1')).toBe('\r\n');
      expect(hash).toBe('frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=');
    });

    it('simple: a body with no trailing CRLF at all gets one added', () => {
      expect(canonicalizeBodySimple(Buffer.from('Hi', 'latin1')).toString('latin1')).toBe('Hi\r\n');
    });

    it('relaxed: collapses internal whitespace runs and strips trailing line whitespace', () => {
      const body = Buffer.from('D \t E\r\n', 'latin1');
      expect(canonicalizeBodyRelaxed(body).toString('latin1')).toBe('D E\r\n');
    });

    it('relaxed: strips trailing blank lines, keeping exactly one trailing CRLF', () => {
      const body = Buffer.from('Hi.\r\n\r\n\r\n', 'latin1');
      expect(canonicalizeBodyRelaxed(body).toString('latin1')).toBe('Hi.\r\n');
    });

    it('relaxed: an empty (or all-blank-line) body canonicalizes to the EMPTY string, unlike simple (matches RFC 6376\'s own SHA-256("") example)', () => {
      const canonicalEmpty = canonicalizeBodyRelaxed(Buffer.alloc(0));
      const canonicalBlankLines = canonicalizeBodyRelaxed(Buffer.from('\r\n\r\n', 'latin1'));
      const hash = crypto.createHash('sha256').update(canonicalEmpty).digest('base64');

      expect(canonicalEmpty.length).toBe(0);
      expect(canonicalBlankLines.length).toBe(0);
      expect(hash).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('relaxed: a body with no trailing CRLF at all gets one added', () => {
      expect(canonicalizeBodyRelaxed(Buffer.from('Hi', 'latin1')).toString('latin1')).toBe('Hi\r\n');
    });
  });
});
