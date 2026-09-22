import { describe, it, expect } from 'vitest';
import * as zlib from 'zlib';
import { analyzeApk, isLikelyApk } from '../ApkAnalyzer';
import { parseAxml } from '../AxmlParser';

/**
 * These tests exercise the REAL binary AXML parser and the REAL zip reader
 * (yauzl) against hand-constructed, spec-faithful fixtures — not mocks. The
 * encoder below implements the same AOSP binary-XML chunk layout the parser
 * consumes (ResChunk_header / ResStringPool_header / ResXMLTree_attrExt),
 * so this is a genuine round-trip test of the documented format, not a
 * tautology against the parser's own assumptions.
 */

// ---- Minimal AXML (binary AndroidManifest.xml) encoder, test-fixture only ----
const CHUNK_STRING_POOL = 0x0001;
const CHUNK_XML = 0x0003;
const CHUNK_XML_START_ELEMENT = 0x0102;
const CHUNK_XML_END_ELEMENT = 0x0103;
const NULL_REF = 0xffffffff;
const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_BOOLEAN = 0x12;

interface AttrSpec { name: string; value: string; type: 'string' | 'int' | 'boolean' }
interface ElSpec { name: string; attrs: AttrSpec[]; children: ElSpec[] }

function collectStrings(el: ElSpec, set: Set<string>) {
  set.add(el.name);
  for (const a of el.attrs) { set.add(a.name); if (a.type === 'string') set.add(a.value); }
  for (const c of el.children) collectStrings(c, set);
}

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
  header.writeUInt16LE(CHUNK_STRING_POOL, 0);
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

function buildElement(el: ElSpec, strIdx: Map<string, number>): Buffer {
  const nameIdx = strIdx.get(el.name)!;
  const attrBufs = el.attrs.map((a) => {
    const buf = Buffer.alloc(20);
    buf.writeUInt32LE(NULL_REF, 0);
    buf.writeUInt32LE(strIdx.get(a.name)!, 4);
    if (a.type === 'string') {
      buf.writeUInt32LE(strIdx.get(a.value)!, 8);
      buf.writeUInt16LE(8, 12);
      buf.writeUInt8(0, 14);
      buf.writeUInt8(TYPE_STRING, 15);
      buf.writeUInt32LE(strIdx.get(a.value)!, 16);
    } else {
      buf.writeUInt32LE(NULL_REF, 8);
      buf.writeUInt16LE(8, 12);
      buf.writeUInt8(0, 14);
      buf.writeUInt8(a.type === 'boolean' ? TYPE_INT_BOOLEAN : TYPE_INT_DEC, 15);
      buf.writeUInt32LE(a.type === 'boolean' ? (a.value === 'true' ? 1 : 0) : parseInt(a.value, 10), 16);
    }
    return buf;
  });

  const attrExt = Buffer.alloc(20);
  attrExt.writeUInt32LE(NULL_REF, 0);
  attrExt.writeUInt32LE(nameIdx, 4);
  attrExt.writeUInt16LE(20, 8);
  attrExt.writeUInt16LE(20, 10);
  attrExt.writeUInt16LE(el.attrs.length, 12);
  attrExt.writeUInt16LE(0, 14);
  attrExt.writeUInt16LE(0, 16);
  attrExt.writeUInt16LE(0, 18);

  const preHeader = Buffer.alloc(8);
  preHeader.writeUInt32LE(0, 0);
  preHeader.writeUInt32LE(NULL_REF, 4);

  const body = Buffer.concat([preHeader, attrExt, ...attrBufs]);
  const header = Buffer.alloc(8);
  header.writeUInt16LE(CHUNK_XML_START_ELEMENT, 0);
  header.writeUInt16LE(16, 2);
  header.writeUInt32LE(8 + body.length, 4);
  const startChunk = Buffer.concat([header, body]);

  const endBody = Buffer.alloc(16);
  endBody.writeUInt32LE(0, 0);
  endBody.writeUInt32LE(NULL_REF, 4);
  endBody.writeUInt32LE(NULL_REF, 8);
  endBody.writeUInt32LE(NULL_REF, 12);
  const endHeader = Buffer.alloc(8);
  endHeader.writeUInt16LE(CHUNK_XML_END_ELEMENT, 0);
  endHeader.writeUInt16LE(16, 2);
  endHeader.writeUInt32LE(8 + endBody.length, 4);
  const endChunk = Buffer.concat([endHeader, endBody]);

  const childChunks = el.children.map((c) => buildElement(c, strIdx));
  return Buffer.concat([startChunk, ...childChunks, endChunk]);
}

function buildAxml(root: ElSpec): Buffer {
  const strSet = new Set<string>();
  collectStrings(root, strSet);
  const strings = Array.from(strSet);
  const strIdx = new Map(strings.map((s, i) => [s, i]));
  const stringPool = buildStringPool(strings);
  const elementBuf = buildElement(root, strIdx);
  const rootHeader = Buffer.alloc(8);
  rootHeader.writeUInt16LE(CHUNK_XML, 0);
  rootHeader.writeUInt16LE(8, 2);
  rootHeader.writeUInt32LE(8 + stringPool.length + elementBuf.length, 4);
  return Buffer.concat([rootHeader, stringPool, elementBuf]);
}

// ---- Minimal STORED-only ZIP builder, test-fixture only ----
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
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(f.data.length, 18);
    local.writeUInt32LE(f.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
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

function minimalManifest(overrides: Partial<{ permissions: string[]; embeddedUrl: string; exported: string }> = {}): Buffer {
  const permissions = overrides.permissions ?? ['android.permission.INTERNET'];
  return buildAxml({
    name: 'manifest',
    attrs: [
      { name: 'package', value: 'com.example.testapp', type: 'string' },
      { name: 'versionCode', value: '7', type: 'int' },
      { name: 'versionName', value: '1.2.3', type: 'string' },
    ],
    children: [
      {
        name: 'uses-sdk',
        attrs: [
          { name: 'minSdkVersion', value: '21', type: 'int' },
          { name: 'targetSdkVersion', value: '33', type: 'int' },
        ],
        children: [],
      },
      ...permissions.map((p) => ({
        name: 'uses-permission',
        attrs: [{ name: 'name', value: p, type: 'string' as const }],
        children: [],
      })),
      {
        name: 'application',
        attrs: overrides.embeddedUrl ? [{ name: 'metaValue', value: overrides.embeddedUrl, type: 'string' as const }] : [],
        children: [
          {
            name: 'activity',
            attrs: [
              { name: 'name', value: 'com.example.testapp.MainActivity', type: 'string' },
              { name: 'exported', value: overrides.exported ?? 'true', type: 'boolean' },
            ],
            children: [],
          },
        ],
      },
    ],
  });
}

describe('isLikelyApk', () => {
  it('requires AndroidManifest.xml as a real entry, not filename/extension', () => {
    expect(isLikelyApk(['AndroidManifest.xml', 'classes.dex'])).toBe(true);
    expect(isLikelyApk(['readme.txt', 'data.bin'])).toBe(false);
    expect(isLikelyApk([])).toBe(false);
  });
});

describe('analyzeApk — valid APK static metadata extraction', () => {
  it('extracts package, version, SDK, permissions, and component metadata', async () => {
    const manifest = minimalManifest();
    const apk = buildStoredZip([
      { name: 'AndroidManifest.xml', data: manifest },
      { name: 'classes.dex', data: Buffer.from('dummy dex content') },
      { name: 'lib/armeabi-v7a/libfoo.so', data: Buffer.from('native') },
    ]);

    const result = await analyzeApk(apk);

    expect(result).not.toBeNull();
    expect(result!.packageName).toBe('com.example.testapp');
    expect(result!.versionCode).toBe('7');
    expect(result!.versionName).toBe('1.2.3');
    expect(result!.minSdkVersion).toBe('21');
    expect(result!.targetSdkVersion).toBe('33');
    expect(result!.permissions).toEqual(['android.permission.INTERNET']);
    expect(result!.suspiciousPermissions).toEqual([]);
    expect(result!.activities).toEqual([{ name: 'com.example.testapp.MainActivity', exported: true }]);
    expect(result!.hasClassesDex).toBe(true);
    expect(result!.nativeLibraries).toEqual(['lib/armeabi-v7a/libfoo.so']);
    expect(result!.manifestParseError).toBeNull();
    expect(result!.analyzerVersion).toBeTruthy();
  });

  it('flags dangerous permissions as suspicious while leaving benign ones alone', async () => {
    const manifest = minimalManifest({
      permissions: ['android.permission.INTERNET', 'android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS'],
    });
    const apk = buildStoredZip([{ name: 'AndroidManifest.xml', data: manifest }]);

    const result = await analyzeApk(apk);

    expect(result!.suspiciousPermissions.sort()).toEqual(
      ['android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS'].sort()
    );
    expect(result!.permissions).toContain('android.permission.INTERNET');
  });

  it('extracts embedded URLs from the manifest string pool', async () => {
    const manifest = minimalManifest({ embeddedUrl: 'https://malicious-c2.example.com/beacon' });
    const apk = buildStoredZip([{ name: 'AndroidManifest.xml', data: manifest }]);

    const result = await analyzeApk(apk);

    expect(result!.embeddedUrls).toContain('https://malicious-c2.example.com/beacon');
  });

  it('detects v1 JAR signing files without decoding certificate contents', async () => {
    const manifest = minimalManifest();
    const apk = buildStoredZip([
      { name: 'AndroidManifest.xml', data: manifest },
      { name: 'META-INF/CERT.RSA', data: Buffer.from('not a real cert, presence-only test') },
      { name: 'META-INF/CERT.SF', data: Buffer.from('sig file') },
    ]);

    const result = await analyzeApk(apk);

    expect(result!.signing.hasV1JarSigning).toBe(true);
    expect(result!.signing.signingFiles).toContain('META-INF/CERT.RSA');
  });

  it('reports no signing when neither v1 files nor a v2 signing block are present', async () => {
    const manifest = minimalManifest();
    const apk = buildStoredZip([{ name: 'AndroidManifest.xml', data: manifest }]);

    const result = await analyzeApk(apk);

    expect(result!.signing.hasV1JarSigning).toBe(false);
    expect(result!.signing.hasV2SigningBlock).toBe(false);
  });
});

describe('analyzeApk — non-APK and malformed input handling', () => {
  it('returns null for an ordinary zip with no AndroidManifest.xml', async () => {
    const zip = buildStoredZip([{ name: 'readme.txt', data: Buffer.from('hello') }]);
    const result = await analyzeApk(zip);
    expect(result).toBeNull();
  });

  it('reports a manifestParseError instead of throwing for a corrupt manifest', async () => {
    const corrupt = Buffer.from('not a real AXML file at all, just garbage bytes 000000');
    const apk = buildStoredZip([{ name: 'AndroidManifest.xml', data: corrupt }]);

    const result = await analyzeApk(apk);

    expect(result).not.toBeNull();
    expect(result!.manifestParseError).toBeTruthy();
    expect(result!.packageName).toBeNull();
  });

  it('safely bounds an oversized AndroidManifest.xml instead of buffering unbounded memory', async () => {
    const oversized = Buffer.alloc(6 * 1024 * 1024, 0x41); // 6MB, over the 5MB safety bound
    const apk = buildStoredZip([{ name: 'AndroidManifest.xml', data: oversized }]);

    const result = await analyzeApk(apk);

    expect(result).not.toBeNull();
    expect(result!.manifestParseError).toMatch(/safety size bound/i);
  }, 15000);
});

describe('parseAxml (direct unit coverage)', () => {
  it('parses nested elements and attribute types (string/int/boolean) correctly', () => {
    const manifest = minimalManifest({ exported: 'false' });
    const { root } = parseAxml(manifest);

    expect(root?.name).toBe('manifest');
    const application = root?.children.find((c) => c.name === 'application');
    const activity = application?.children.find((c) => c.name === 'activity');
    expect(activity?.attributes.find((a) => a.name === 'exported')?.value).toBe('false');
  });
});
