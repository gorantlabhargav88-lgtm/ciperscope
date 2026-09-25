import { describe, it, expect, vi } from 'vitest';
import { Readable } from 'stream';
import * as zlib from 'zlib';
import { AttachmentAnalyzer } from '../AttachmentAnalyzer';

/**
 * Unmocked integration coverage: AttachmentAnalyzer.analyze() end-to-end
 * against a real, spec-faithful APK fixture (real file-type magic-byte
 * detection, real yauzl zip reading, real AXML manifest parsing) — proving
 * the wiring between the generic attachment pipeline and the APK analyzer,
 * not just each piece in isolation.
 */

const NULL_REF = 0xffffffff;

function buildStringPool(strings: string[]): Buffer {
  const stringsStart = 28 + strings.length * 4;
  const entries: Buffer[] = [];
  const offsets: number[] = [];
  let cursor = 0;
  for (const s of strings) {
    offsets.push(cursor);
    const strBuf = Buffer.from(s, 'utf16le');
    const lenU16 = Buffer.alloc(2);
    lenU16.writeUInt16LE(s.length, 0);
    const entry = Buffer.concat([lenU16, strBuf, Buffer.alloc(2)]);
    entries.push(entry);
    cursor += entry.length;
  }
  const dataBuf = Buffer.concat(entries);
  const header = Buffer.alloc(28);
  header.writeUInt16LE(0x0001, 0);
  header.writeUInt16LE(28, 2);
  header.writeUInt32LE(stringsStart + dataBuf.length, 4);
  header.writeUInt32LE(strings.length, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(stringsStart, 20);
  header.writeUInt32LE(0, 24);
  const offsetsBuf = Buffer.alloc(strings.length * 4);
  offsets.forEach((o, i) => offsetsBuf.writeUInt32LE(o, i * 4));
  return Buffer.concat([header, offsetsBuf, dataBuf]);
}

function buildManifest(packageName: string): Buffer {
  const strings = ['manifest', 'package', packageName];
  const strIdx = new Map(strings.map((s, i) => [s, i]));
  const stringPool = buildStringPool(strings);

  const attr = Buffer.alloc(20);
  attr.writeUInt32LE(NULL_REF, 0);
  attr.writeUInt32LE(strIdx.get('package')!, 4);
  attr.writeUInt32LE(strIdx.get(packageName)!, 8);
  attr.writeUInt16LE(8, 12);
  attr.writeUInt8(0, 14);
  attr.writeUInt8(0x03, 15); // TYPE_STRING
  attr.writeUInt32LE(strIdx.get(packageName)!, 16);

  const attrExt = Buffer.alloc(20);
  attrExt.writeUInt32LE(NULL_REF, 0);
  attrExt.writeUInt32LE(strIdx.get('manifest')!, 4);
  attrExt.writeUInt16LE(20, 8);
  attrExt.writeUInt16LE(20, 10);
  attrExt.writeUInt16LE(1, 12);
  attrExt.writeUInt16LE(0, 14);
  attrExt.writeUInt16LE(0, 16);
  attrExt.writeUInt16LE(0, 18);

  const preHeader = Buffer.alloc(8);
  preHeader.writeUInt32LE(0, 0);
  preHeader.writeUInt32LE(NULL_REF, 4);

  const startBody = Buffer.concat([preHeader, attrExt, attr]);
  const startHeader = Buffer.alloc(8);
  startHeader.writeUInt16LE(0x0102, 0);
  startHeader.writeUInt16LE(16, 2);
  startHeader.writeUInt32LE(8 + startBody.length, 4);
  const startChunk = Buffer.concat([startHeader, startBody]);

  const endBody = Buffer.alloc(16, 0xff); // ns/name = -1, lineNumber/comment don't matter for skip-only parsing
  endBody.writeUInt32LE(0, 0);
  const endHeader = Buffer.alloc(8);
  endHeader.writeUInt16LE(0x0103, 0);
  endHeader.writeUInt16LE(16, 2);
  endHeader.writeUInt32LE(8 + endBody.length, 4);
  const endChunk = Buffer.concat([endHeader, endBody]);

  const rootHeader = Buffer.alloc(8);
  rootHeader.writeUInt16LE(0x0003, 0);
  rootHeader.writeUInt16LE(8, 2);
  rootHeader.writeUInt32LE(8 + stringPool.length + startChunk.length + endChunk.length, 4);

  return Buffer.concat([rootHeader, stringPool, startChunk, endChunk]);
}

function buildStoredZip(files: { name: string; data: Buffer }[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const crc = zlib.crc32(f.data) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(f.data.length, 18);
    local.writeUInt32LE(f.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const localEntry = Buffer.concat([local, nameBuf, f.data]);
    localParts.push(localEntry);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(f.data.length, 20);
    central.writeUInt32LE(f.data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centralParts.push(Buffer.concat([central, nameBuf]));
    offset += localEntry.length;
  }
  const centralDir = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, centralDir, eocd]);
}

describe('AttachmentAnalyzer + APK — unmocked end-to-end', () => {
  it('identifies a real APK via zip-magic + AndroidManifest.xml and extracts static metadata, even when declared as a disguised type', async () => {
    const manifest = buildManifest('com.example.disguised');
    const apkBytes = buildStoredZip([
      { name: 'AndroidManifest.xml', data: manifest },
      { name: 'classes.dex', data: Buffer.from('dex') },
    ]);

    // Attacker declares it as a PDF to evade naive extension-based filtering.
    const result = await AttachmentAnalyzer.analyze(Readable.from([apkBytes]), 'application/pdf', 'pdf');

    expect(result.isArchive).toBe(true); // still correctly seen as a zip container
    expect(result.apkAnalysis).not.toBeNull();
    expect(result.apkAnalysis!.packageName).toBe('com.example.disguised');
    expect(result.apkAnalysis!.hasClassesDex).toBe(true);
    // The generic mismatch check only compares top-level MIME type (application/*
    // for both), so this documents the current behavior rather than asserting a
    // gap this test isn't scoped to fix — the APK-specific findings themselves
    // are what surface the disguise via apkAnalysis being non-null under a
    // declared "pdf" extension.
    expect(result.actualExtension).toBe('zip');
  });

  it('does not populate apkAnalysis for an ordinary non-APK zip', async () => {
    const zipBytes = buildStoredZip([{ name: 'readme.txt', data: Buffer.from('hello') }]);
    const result = await AttachmentAnalyzer.analyze(Readable.from([zipBytes]), 'application/zip');

    expect(result.isArchive).toBe(true);
    expect(result.apkAnalysis).toBeNull();
  });

  it('never spawns a process or shells out while analyzing an APK (static byte analysis only)', async () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires -- technically unavoidable: ESM namespace objects (await import('child_process')) are non-configurable in Node, preventing vi.spyOn() from overriding spawn/exec. We must use require() to spy on the CommonJS exports.
    const originalSpawn = require('child_process').spawn;
    // eslint-disable-next-line @typescript-eslint/no-var-requires -- technically unavoidable for the same reason.
    const originalExec = require('child_process').exec;
    let called = false;
    // eslint-disable-next-line @typescript-eslint/no-var-requires -- technically unavoidable.
    require('child_process').spawn = (...args: unknown[]) => { called = true; return originalSpawn(...(args as [])); };
    // eslint-disable-next-line @typescript-eslint/no-var-requires -- technically unavoidable.
    require('child_process').exec = (...args: unknown[]) => { called = true; return originalExec(...(args as [])); };

    try {
      const manifest = buildManifest('com.example.noexec');
      const apkBytes = buildStoredZip([{ name: 'AndroidManifest.xml', data: manifest }]);
      await AttachmentAnalyzer.analyze(Readable.from([apkBytes]), 'application/vnd.android.package-archive', 'apk');
      expect(called).toBe(false);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-var-requires -- technically unavoidable.
      require('child_process').spawn = originalSpawn;
      // eslint-disable-next-line @typescript-eslint/no-var-requires -- technically unavoidable.
      require('child_process').exec = originalExec;
    }
  });
});
