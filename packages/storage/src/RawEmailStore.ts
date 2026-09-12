import { Readable } from 'stream';

export interface RawEmailStore {
  /**
   * Stores a raw email stream.
   * @param key The deterministic storage key (e.g., organizationId/sha256.eml)
   * @param stream The readable stream of the raw email bytes
   * @returns Resolves when the upload is complete
   */
  put(key: string, stream: Readable): Promise<void>;

  /**
   * Retrieves a raw email stream.
   * @param key The storage key
   * @returns A readable stream of the raw email bytes
   */
  get(key: string): Promise<Readable>;

  /**
   * Checks if an email exists at the given key.
   * @param key The storage key
   * @returns True if the object exists
   */
  exists(key: string): Promise<boolean>;

  /**
   * Deletes a raw email.
   * @param key The storage key
   * @returns Resolves when deleted
   */
  delete(key: string): Promise<void>;
}
