import { Jimp } from 'jimp';
import jsQR, { QRCode } from 'jsqr';
import { logger } from '@ciperscope/logger';

export type QrPayloadType = 'URL' | 'TEXT' | 'OTHER';

export interface QrCodeResult {
  payload: string;
  type: QrPayloadType;
}

export interface QrAnalysisResult {
  detected: boolean;
  codes: QrCodeResult[];
  errors?: string[];
}

// All bounds are deliberately conservative — this decodes attacker-controlled
// image bytes, so every dimension is capped before any decode work happens.
const MAX_IMAGE_BUFFER_BYTES = 15 * 1024 * 1024; // 15MB — bounds decode CPU cost
const MAX_IMAGE_DIMENSION_PX = 8000; // per side
const MAX_IMAGE_PIXELS = 40_000_000; // ~40MP
const MAX_QR_CODES = 10;
const MAX_PAYLOAD_LENGTH = 4096;

function classifyPayload(payload: string): QrPayloadType {
  const trimmed = payload.trim();
  if (trimmed.length === 0) return 'OTHER';
  if (/^https?:\/\//i.test(trimmed)) return 'URL';
  return 'TEXT';
}

/** Blanks the pixel region a decoded QR code occupied so a subsequent scan
 *  pass over the same tile can find a different, overlapping code. */
function blankRegion(pixels: Uint8ClampedArray, width: number, height: number, location: QRCode['location']): void {
  const xs = [location.topLeftCorner.x, location.topRightCorner.x, location.bottomLeftCorner.x, location.bottomRightCorner.x];
  const ys = [location.topLeftCorner.y, location.topRightCorner.y, location.bottomLeftCorner.y, location.bottomRightCorner.y];
  const margin = 2;
  const minX = Math.max(0, Math.floor(Math.min(...xs)) - margin);
  const maxX = Math.min(width - 1, Math.ceil(Math.max(...xs)) + margin);
  const minY = Math.max(0, Math.floor(Math.min(...ys)) - margin);
  const maxY = Math.min(height - 1, Math.ceil(Math.max(...ys)) + margin);

  for (let y = minY; y <= maxY; y++) {
    for (let x = minX; x <= maxX; x++) {
      const idx = (y * width + x) * 4;
      pixels[idx] = 255;
      pixels[idx + 1] = 255;
      pixels[idx + 2] = 255;
      pixels[idx + 3] = 255;
    }
  }
}

interface Tile {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * jsQR reliably finds at most one QR code per full-frame scan, and its
 * finder-pattern locator can fail entirely (not just under-count) when
 * several codes' finder patterns are visible in the same frame at once —
 * a known limitation, confirmed empirically against this exact library
 * version, not something a single blank-and-rescan pass over the full
 * frame can fix if the very first full-frame scan already returns nothing.
 *
 * Instead this scans a fixed, bounded set of tiles — the full frame plus
 * four overlapping half-frames (left/right/top/bottom) — so two QR codes
 * placed side by side or stacked each end up alone in at least one tile.
 * The tile set is fixed regardless of image content, so the number of
 * jsQR invocations per image is bounded and deterministic.
 */
function buildScanTiles(width: number, height: number): Tile[] {
  const tiles: Tile[] = [{ x: 0, y: 0, w: width, h: height }];
  if (width >= 2) {
    const halfW = Math.ceil(width * 0.6);
    tiles.push({ x: 0, y: 0, w: halfW, h: height });
    tiles.push({ x: width - halfW, y: 0, w: halfW, h: height });
  }
  if (height >= 2) {
    const halfH = Math.ceil(height * 0.6);
    tiles.push({ x: 0, y: 0, w: width, h: halfH });
    tiles.push({ x: 0, y: height - halfH, w: width, h: halfH });
  }
  return tiles;
}

function extractTilePixels(source: Buffer, srcWidth: number, tile: Tile): Uint8ClampedArray {
  const out = new Uint8ClampedArray(tile.w * tile.h * 4);
  const rowBytes = tile.w * 4;
  for (let row = 0; row < tile.h; row++) {
    const srcStart = ((tile.y + row) * srcWidth + tile.x) * 4;
    const destStart = row * rowBytes;
    for (let b = 0; b < rowBytes; b++) {
      out[destStart + b] = source[srcStart + b];
    }
  }
  return out;
}

/**
 * Statically decodes QR codes from an image attachment's bytes. Never
 * executes, opens, or fetches decoded content — a decoded payload is
 * returned as inert data only, classified as a type hint (URL/TEXT/OTHER)
 * for the caller to route through the existing, unmodified URL-analysis
 * pipeline. No network access ever happens inside this function.
 */
export async function analyzeQrCodes(buffer: Buffer): Promise<QrAnalysisResult> {
  if (buffer.length === 0) {
    return { detected: false, codes: [] };
  }

  if (buffer.length > MAX_IMAGE_BUFFER_BYTES) {
    return { detected: false, codes: [], errors: ['Image exceeds the maximum size accepted for QR analysis'] };
  }

  let bitmap: { data: Buffer; width: number; height: number };
  try {
    const image = await Jimp.read(buffer);
    bitmap = image.bitmap;
  } catch (e: unknown) {
    logger.warn({ err: e }, 'Failed to decode image for QR analysis');
    return { detected: false, codes: [], errors: ['Failed to decode image'] };
  }

  const { width, height, data } = bitmap;
  if (width <= 0 || height <= 0) {
    return { detected: false, codes: [] };
  }
  if (width > MAX_IMAGE_DIMENSION_PX || height > MAX_IMAGE_DIMENSION_PX || width * height > MAX_IMAGE_PIXELS) {
    return { detected: false, codes: [], errors: ['Image exceeds safe dimension/pixel bounds for QR analysis'] };
  }

  const codes: QrCodeResult[] = [];
  const seenPayloads = new Set<string>();
  const errors: string[] = [];
  const tiles = buildScanTiles(width, height);

  for (const tile of tiles) {
    if (codes.length >= MAX_QR_CODES) break;

    const tilePixels = extractTilePixels(data, width, tile);

    // Within a tile, blank-and-rescan still helps catch two codes that
    // happen to both land in the same tile (e.g. two codes stacked
    // diagonally) — bounded by the same MAX_QR_CODES ceiling overall.
    for (let i = 0; i < MAX_QR_CODES && codes.length < MAX_QR_CODES; i++) {
      let found: ReturnType<typeof jsQR>;
      try {
        found = jsQR(tilePixels, tile.w, tile.h, { inversionAttempts: 'attemptBoth' });
      } catch (e: unknown) {
        logger.warn({ err: e }, 'QR decoder threw while scanning image');
        errors.push('QR decoder failed');
        break;
      }

      if (!found) break;

      if (!seenPayloads.has(found.data)) {
        seenPayloads.add(found.data);
        const payload = found.data.length > MAX_PAYLOAD_LENGTH ? found.data.slice(0, MAX_PAYLOAD_LENGTH) : found.data;
        codes.push({ payload, type: classifyPayload(payload) });
      }

      blankRegion(tilePixels, tile.w, tile.h, found.location);
    }
  }

  return { detected: codes.length > 0, codes, errors: errors.length > 0 ? errors : undefined };
}
