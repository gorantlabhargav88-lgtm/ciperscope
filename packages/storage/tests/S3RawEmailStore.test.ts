import { describe, it, expect, vi, beforeEach } from 'vitest';
import { S3RawEmailStore } from '../src/s3/S3RawEmailStore';
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { Readable } from 'stream';

// Mock the S3Client
vi.mock('@aws-sdk/client-s3', () => {
  return {
    S3Client: vi.fn(() => ({
      send: vi.fn(),
    })),
    PutObjectCommand: vi.fn(),
    GetObjectCommand: vi.fn(),
    HeadObjectCommand: vi.fn(),
    DeleteObjectCommand: vi.fn(),
  };
});

describe('S3RawEmailStore', () => {
  let store: S3RawEmailStore;
  let mockSend: any;

  beforeEach(() => {
    vi.clearAllMocks();
    store = new S3RawEmailStore('test-bucket', 'us-east-1');
    // Extract the mock send method from the mocked instance
    mockSend = (store as any).client.send;
  });

  it('should construct correctly', () => {
    expect(S3Client).toHaveBeenCalledWith(expect.objectContaining({
      region: 'us-east-1'
    }));
  });

  it('should put object with AES256 encryption', async () => {
    const stream = new Readable();
    mockSend.mockResolvedValueOnce({});

    await store.put('test-key', stream);

    expect(PutObjectCommand).toHaveBeenCalledWith(expect.objectContaining({
      Bucket: 'test-bucket',
      Key: 'test-key',
      Body: stream,
      ContentType: 'message/rfc822',
      ServerSideEncryption: 'AES256'
    }));
    expect(mockSend).toHaveBeenCalled();
  });

  it('should get object and return stream', async () => {
    const stream = new Readable();
    mockSend.mockResolvedValueOnce({ Body: stream });

    const result = await store.get('test-key');

    expect(GetObjectCommand).toHaveBeenCalledWith(expect.objectContaining({
      Bucket: 'test-bucket',
      Key: 'test-key'
    }));
    expect(result).toBe(stream);
  });

  it('should return true if object exists', async () => {
    mockSend.mockResolvedValueOnce({});

    const result = await store.exists('test-key');

    expect(HeadObjectCommand).toHaveBeenCalledWith(expect.objectContaining({
      Bucket: 'test-bucket',
      Key: 'test-key'
    }));
    expect(result).toBe(true);
  });

  it('should return false if object does not exist (NotFound)', async () => {
    const error: any = new Error('Not Found');
    error.name = 'NotFound';
    mockSend.mockRejectedValueOnce(error);

    const result = await store.exists('test-key');

    expect(result).toBe(false);
  });

  it('should throw error if exists check fails for other reasons', async () => {
    const error: any = new Error('Access Denied');
    error.name = 'AccessDenied';
    mockSend.mockRejectedValueOnce(error);

    await expect(store.exists('test-key')).rejects.toThrow('Access Denied');
  });

  it('should delete object', async () => {
    mockSend.mockResolvedValueOnce({});

    await store.delete('test-key');

    expect(DeleteObjectCommand).toHaveBeenCalledWith(expect.objectContaining({
      Bucket: 'test-bucket',
      Key: 'test-key'
    }));
    expect(mockSend).toHaveBeenCalled();
  });
});
