import { describe, it, expect, vi } from 'vitest';
import { logger } from './index';

describe('Logger Redaction', () => {
  it('should redact sensitive fields', () => {
    // We can test this by spying on the internal pino stream or checking the logger output,
    // but a simple way is just to verify the logger object was created without crashing.
    // However, to truly test redaction, we can create a child logger with a mock stream.
    const stream = {
      write: vi.fn(),
    };
    const pino = require('pino');
    const { loggerOptions } = require('./index');
    
    const testLogger = pino(loggerOptions, stream);
    
    testLogger.info({
      password: 'super-secret-password',
      token: 'jwt-token-123',
      publicInfo: 'hello',
    }, 'Test log');
    
    expect(stream.write).toHaveBeenCalled();
    const logOutput = JSON.parse(stream.write.mock.calls[0][0]);
    
    expect(logOutput.password).toBe('[Redacted]');
    expect(logOutput.token).toBe('[Redacted]');
    expect(logOutput.publicInfo).toBe('hello');
  });
});
