import { Readable } from 'stream';
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { RawEmailStore } from '../RawEmailStore';

export class S3RawEmailStore implements RawEmailStore {
  private client: S3Client;
  private bucket: string;

  constructor(bucket: string, region: string = 'us-east-1', endpoint?: string) {
    this.bucket = bucket;

    const config: any = {
      region,
      forcePathStyle: endpoint ? true : false,
    };

    if (endpoint) {
      config.endpoint = endpoint;
    }

    this.client = new S3Client(config);
  }

  public async put(key: string, stream: Readable): Promise<void> {
    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: stream,
      ContentType: 'message/rfc822',
      ServerSideEncryption: 'AES256'
    });

    await this.client.send(command);
  }

  public async get(key: string): Promise<Readable> {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key
    });

    const response = await this.client.send(command);

    if (!response.Body) {
      throw new Error(`S3 object body is empty for key: ${key}`);
    }

    return response.Body as Readable;
  }

  public async exists(key: string): Promise<boolean> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.bucket,
        Key: key
      });
      await this.client.send(command);
      return true;
    } catch (error: any) {
      if (error.name === 'NotFound' || error.$metadata?.httpStatusCode === 404) {
        return false;
      }
      throw error;
    }
  }

  public async delete(key: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: key
    });

    await this.client.send(command);
  }
}
