import fs from 'fs';
import path from 'path';
import { pipeline } from 'stream/promises';
import { Readable } from 'stream';
import { RawEmailStore } from '../RawEmailStore';
import { logger } from '@ciperscope/logger';

export class LocalRawEmailStore implements RawEmailStore {
  private readonly baseDir: string;

  constructor(baseDir?: string) {
    // Default to a local data directory if not provided
    this.baseDir = baseDir || path.resolve(process.cwd(), '.data/emails');
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true });
    }
  }

  private resolvePath(key: string): string {
    // Prevent path traversal by validating the key
    if (key.includes('..') || path.isAbsolute(key)) {
      throw new Error('Path traversal attempt detected');
    }

    const fullPath = path.resolve(this.baseDir, key);
    
    // Ensure the resolved path is strictly within baseDir
    if (!fullPath.startsWith(this.baseDir)) {
      throw new Error('Path traversal attempt detected');
    }
    
    return fullPath;
  }

  async put(key: string, stream: Readable): Promise<void> {
    const filePath = this.resolvePath(key);
    const dir = path.dirname(filePath);
    
    if (!fs.existsSync(dir)) {
      await fs.promises.mkdir(dir, { recursive: true });
    }

    const writeStream = fs.createWriteStream(filePath);
    
    try {
      await pipeline(stream, writeStream);
      logger.debug({ key, filePath }, 'Stored raw email locally');
    } catch (error) {
      logger.error({ key, err: error }, 'Failed to store raw email locally');
      // Cleanup partial file on failure
      if (fs.existsSync(filePath)) {
        await fs.promises.unlink(filePath).catch(() => {});
      }
      throw error;
    }
  }

  async get(key: string): Promise<Readable> {
    const filePath = this.resolvePath(key);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Email not found: ${key}`);
    }
    return fs.createReadStream(filePath);
  }

  async exists(key: string): Promise<boolean> {
    const filePath = this.resolvePath(key);
    try {
      await fs.promises.access(filePath, fs.constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  async delete(key: string): Promise<void> {
    const filePath = this.resolvePath(key);
    if (fs.existsSync(filePath)) {
      await fs.promises.unlink(filePath);
      logger.debug({ key }, 'Deleted raw email locally');
    }
  }
}
