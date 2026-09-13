import { describe, it, expect, vi } from 'vitest';
import { AttachmentAnalyzer } from '../AttachmentAnalyzer';
import { Readable } from 'stream';
import * as crypto from 'crypto';

vi.mock('file-type', () => ({
  fromBuffer: vi.fn((buf: Buffer) => {
    const hex = buf.subarray(0, 4).toString('hex');
    if (hex === '89504e47') return Promise.resolve({ mime: 'image/png', ext: 'png' });
    if (hex === '504b0304') return Promise.resolve({ mime: 'application/zip', ext: 'zip' });
    return Promise.resolve(null);
  })
}));

vi.mock('yauzl', () => ({
  fromBuffer: vi.fn((buffer, options, callback) => {
    const zipfile = {
      on: (event: string, handler: () => void) => {
        if (event === 'end') {
          setTimeout(handler, 0);
        }
      },
      readEntry: vi.fn(),
      close: vi.fn()
    };
    callback(null, zipfile);
  })
}));

describe('AttachmentAnalyzer', () => {
  it('computes correct SHA-256 for a stream', async () => {
    const data = 'Hello World';
    const stream = Readable.from([Buffer.from(data)]);
    const expectedHash = crypto.createHash('sha256').update(data).digest('hex');

    const result = await AttachmentAnalyzer.analyze(stream, 'text/plain');
    
    expect(result.sha256).toBe(expectedHash);
    expect(result.sizeBytes).toBe(data.length);
  });

  it('detects magic bytes mismatch for a PDF that is actually a PNG', async () => {
    // PNG magic bytes
    const pngHeader = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
    const stream = Readable.from([pngHeader]);

    const result = await AttachmentAnalyzer.analyze(stream, 'application/pdf', 'pdf');
    
    expect(result.magicBytes).toBe('89504e470d0a1a0a');
    // Since we check extension mismatch (declExtLower === 'pdf' && !actualMimeType.includes('pdf'))
    // isMismatch should be true.
    expect(result.isMismatch).toBe(true);
  });
  
  it('detects ZIP archives and safely inspects without extraction', async () => {
    const zipBuffer = Buffer.from('504b03040000000000000000000000000000000000000000', 'hex');
    const stream = Readable.from([zipBuffer]);

    const result = await AttachmentAnalyzer.analyze(stream, 'application/zip');
    
    expect(result.isArchive).toBe(true);
    expect(result.archiveMetadata).toBeDefined();
    expect(result.archiveMetadata.entryCount).toBe(0);
    expect(result.archiveMetadata.hasTraversal).toBe(false);
  });
});
