/**
 * Parser for Android's binary XML format ("AXML"), used for AndroidManifest.xml
 * inside APK files. This operates purely on an in-memory Buffer — it never
 * shells out, never touches the filesystem outside the buffer, and never
 * invokes any Android tooling. It is read-only static analysis of bytes.
 *
 * Format reference: AOSP frameworks/base/include/androidfw/ResourceTypes.h
 * (ResChunk_header / ResStringPool_header / ResXMLTree_node / ResXMLTree_attrExt).
 * This implements only what CipherScope needs to extract manifest metadata:
 * the string pool and the XML element/attribute tree. Resource-table
 * (resources.arsc) resolution of `@resourceId` references is out of scope —
 * such attribute values are reported as an unresolved `@0x...` reference
 * rather than guessed at.
 */

const CHUNK_STRING_POOL = 0x0001;
const CHUNK_XML = 0x0003;
const CHUNK_XML_START_NAMESPACE = 0x0100;
const CHUNK_XML_END_NAMESPACE = 0x0101;
const CHUNK_XML_START_ELEMENT = 0x0102;
const CHUNK_XML_END_ELEMENT = 0x0103;
const CHUNK_XML_CDATA = 0x0104;
const CHUNK_XML_RESOURCE_MAP = 0x0180;

const UTF8_FLAG = 1 << 8;

const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

const MAX_ELEMENTS = 20_000; // bound against pathological/malicious manifests
const NULL_REF = 0xffffffff;

export interface AxmlAttribute {
  namespace: string | null;
  name: string;
  value: string | null;
}

export interface AxmlElement {
  name: string;
  attributes: AxmlAttribute[];
  children: AxmlElement[];
}

export interface AxmlParseResult {
  root: AxmlElement | null;
  /** Every literal string in the pool, for deterministic secondary scans (e.g. embedded URLs). */
  strings: string[];
}

class BoundedReader {
  constructor(private readonly buf: Buffer) {}

  u16(offset: number): number {
    if (offset < 0 || offset + 2 > this.buf.length) throw new RangeError('AXML: read past end of buffer (u16)');
    return this.buf.readUInt16LE(offset);
  }

  u32(offset: number): number {
    if (offset < 0 || offset + 4 > this.buf.length) throw new RangeError('AXML: read past end of buffer (u32)');
    return this.buf.readUInt32LE(offset);
  }

  get length(): number {
    return this.buf.length;
  }

  slice(start: number, end: number): Buffer {
    if (start < 0 || end > this.buf.length || end < start) {
      throw new RangeError('AXML: invalid slice range');
    }
    return this.buf.subarray(start, end);
  }
}

function parseStringPool(reader: BoundedReader, chunkStart: number): string[] {
  const headerSize = reader.u16(chunkStart + 2);
  const chunkSize = reader.u32(chunkStart + 4);
  const stringCount = reader.u32(chunkStart + 8);
  const flags = reader.u32(chunkStart + 16);
  const stringsStart = reader.u32(chunkStart + 20);
  const isUtf8 = (flags & UTF8_FLAG) !== 0;

  if (headerSize < 8 || chunkSize < headerSize) {
    throw new RangeError('AXML: malformed string pool header');
  }

  const offsetsBase = chunkStart + headerSize;
  const dataBase = chunkStart + stringsStart;
  const strings: string[] = [];

  for (let i = 0; i < stringCount; i++) {
    const relOffset = reader.u32(offsetsBase + i * 4);
    const entryStart = dataBase + relOffset;
    strings.push(readPoolString(reader, entryStart, isUtf8));
  }

  return strings;
}

function readPoolString(reader: BoundedReader, start: number, isUtf8: boolean): string {
  if (isUtf8) {
    // UTF-8 pool entries: variable-length "character length" then variable-length
    // "byte length" (each 1 or 2 bytes, high bit of the first byte signals 2-byte form).
    let offset = start;
    const [, charLenBytes] = readUtf8VarLen(reader, offset);
    offset += charLenBytes;
    const [byteLen, byteLenBytes] = readUtf8VarLen(reader, offset);
    offset += byteLenBytes;
    const bytes = reader.slice(offset, offset + byteLen);
    return bytes.toString('utf8');
  }

  // UTF-16LE pool entries: variable-length char-count prefix (1 or 2 uint16s),
  // then that many UTF-16 code units, then a null terminator.
  let offset = start;
  const first = reader.u16(offset);
  let charLen: number;
  if ((first & 0x8000) !== 0) {
    const second = reader.u16(offset + 2);
    charLen = ((first & 0x7fff) << 16) | second;
    offset += 4;
  } else {
    charLen = first;
    offset += 2;
  }
  const bytes = reader.slice(offset, offset + charLen * 2);
  return bytes.toString('utf16le');
}

function readUtf8VarLen(reader: BoundedReader, offset: number): [number, number] {
  const first = reader.slice(offset, offset + 1)[0];
  if ((first & 0x80) !== 0) {
    const second = reader.slice(offset + 1, offset + 2)[0];
    return [((first & 0x7f) << 8) | second, 2];
  }
  return [first, 1];
}

function resolveAttrValue(
  strings: string[],
  rawValueIdx: number,
  dataType: number,
  data: number
): string | null {
  if (rawValueIdx !== NULL_REF) {
    return strings[rawValueIdx] ?? null;
  }
  switch (dataType) {
    case TYPE_STRING:
      return strings[data] ?? null;
    case TYPE_INT_BOOLEAN:
      return data !== 0 ? 'true' : 'false';
    case TYPE_INT_DEC:
    case TYPE_INT_HEX:
      return String(data);
    default:
      // Resource reference or other typed value we don't resolve without
      // resources.arsc — report as an explicit unresolved reference rather
      // than fabricating a value.
      return `@0x${data.toString(16)}`;
  }
}

/** Parses an AndroidManifest.xml AXML buffer. Never throws for structurally-odd
 *  but bounded input beyond a RangeError, which callers should catch and treat
 *  as "malformed APK" rather than a crash. */
export function parseAxml(buffer: Buffer): AxmlParseResult {
  const reader = new BoundedReader(buffer);

  if (reader.length < 8) throw new RangeError('AXML: buffer too small');
  const rootType = reader.u16(0);
  const rootSize = reader.u32(4);
  if (rootType !== CHUNK_XML) throw new RangeError('AXML: not a binary XML document');
  if (rootSize > reader.length) throw new RangeError('AXML: declared size exceeds buffer');

  let strings: string[] = [];
  let offset = 8;
  const stack: AxmlElement[] = [];
  let root: AxmlElement | null = null;
  let elementCount = 0;

  while (offset + 8 <= rootSize) {
    const type = reader.u16(offset);
    const headerSize = reader.u16(offset + 2);
    const size = reader.u32(offset + 4);

    if (size < 8 || headerSize < 8 || offset + size > rootSize) {
      throw new RangeError('AXML: malformed chunk header (no forward progress guarantee)');
    }

    if (type === CHUNK_STRING_POOL) {
      strings = parseStringPool(reader, offset);
    } else if (type === CHUNK_XML_RESOURCE_MAP) {
      // Resource ID map — not needed for our attribute resolution strategy (we
      // resolve names via the string pool directly), safe to skip.
    } else if (type === CHUNK_XML_START_ELEMENT) {
      if (++elementCount > MAX_ELEMENTS) {
        throw new RangeError('AXML: exceeded max element count (possible malicious manifest)');
      }
      const nameIdx = reader.u32(offset + headerSize + 4);
      const name = strings[nameIdx] ?? `unknown_${nameIdx}`;

      const attributeStart = reader.u16(offset + headerSize + 8);
      const attributeSize = reader.u16(offset + headerSize + 10);
      const attributeCount = reader.u16(offset + headerSize + 12);
      const attrsBase = offset + headerSize + attributeStart;

      const attributes: AxmlAttribute[] = [];
      for (let i = 0; i < attributeCount; i++) {
        const attrOffset = attrsBase + i * attributeSize;
        if (attrOffset + 20 > offset + size) break; // bounded by this chunk's own declared size
        const nsIdx = reader.u32(attrOffset);
        const attrNameIdx = reader.u32(attrOffset + 4);
        const rawValueIdx = reader.u32(attrOffset + 8);
        // Res_value layout at attrOffset+12: uint16 size, uint8 res0, uint8 dataType, uint32 data.
        const dataType = buffer.readUInt8(attrOffset + 15);
        const data = reader.u32(attrOffset + 16);

        attributes.push({
          namespace: nsIdx !== NULL_REF ? strings[nsIdx] ?? null : null,
          name: strings[attrNameIdx] ?? `attr_${attrNameIdx}`,
          value: resolveAttrValue(strings, rawValueIdx, dataType, data),
        });
      }

      const element: AxmlElement = { name, attributes, children: [] };
      if (stack.length > 0) {
        stack[stack.length - 1].children.push(element);
      } else if (!root) {
        root = element;
      }
      stack.push(element);
    } else if (type === CHUNK_XML_END_ELEMENT) {
      stack.pop();
    } else if (
      type === CHUNK_XML_START_NAMESPACE ||
      type === CHUNK_XML_END_NAMESPACE ||
      type === CHUNK_XML_CDATA
    ) {
      // Not needed for the metadata CipherScope extracts.
    }
    // Unknown chunk types are silently skipped by advancing past `size`,
    // which every well-formed chunk (including ones we don't recognize)
    // guarantees via its own ResChunk_header.

    offset += size;
  }

  return { root, strings };
}
