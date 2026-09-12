import * as argon2 from 'argon2';
import crypto from 'crypto';

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  return argon2.verify(hash, plain);
}

export function generateOpaqueToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
