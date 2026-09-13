import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ThreatAnalyzer } from '../ThreatAnalyzer';

import { PrismaClient } from '@ciperscope/database';
import { LocalRawEmailStore } from '@ciperscope/storage';

describe('ThreatAnalyzer', () => {
  let mockPrisma: PrismaClient;
  let mockStore: LocalRawEmailStore;

  beforeEach(() => {
    mockPrisma = {
      email: {
        findUnique: vi.fn(),
        update: vi.fn(),
      },
      emailUrl: {
        createMany: vi.fn(),
      },
      emailAttachment: {
        createMany: vi.fn(),
        update: vi.fn(),
      },
      $transaction: vi.fn((cb) => cb(mockPrisma)),
    } as unknown as PrismaClient;

    mockStore = {
      exists: vi.fn(),
      get: vi.fn(),
    } as unknown as LocalRawEmailStore;
  });

  it('throws if email is not found', async () => {
    mockPrisma.email.findUnique.mockResolvedValue(null);
    const analyzer = new ThreatAnalyzer(mockPrisma, mockStore);
    await expect(analyzer.analyzeEmail('123')).rejects.toThrow('Email 123 not found');
  });

  // More complex tests would require mocking simpleParser from mailparser.
  // The important part is that we have coverage for the pure logic in UrlExtractor and AttachmentAnalyzer.
});
