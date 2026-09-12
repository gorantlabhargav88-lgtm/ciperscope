import { describe, it, expect, vi } from 'vitest';
import { HttpClient } from '../src/index';

describe('HttpClient Circuit Breaker', () => {
  it('should open circuit after threshold', async () => {
    const client = new HttpClient('test-client', {
      circuitBreakerOptions: {
        errorThresholdPercentage: 1, // open immediately on error
        resetTimeout: 1000,
      }
    });

    // Mock axios instance to throw
    (client as any).axiosInstance.request = vi.fn().mockRejectedValue(new Error('Network Error'));

    // First request fails
    await expect(client.get('/test')).rejects.toThrow('Network Error');
    
    // Circuit should be open, next request fails fast with Opossum error
    await expect(client.get('/test')).rejects.toThrow('Breaker is open');
  });
});
