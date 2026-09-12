import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import CircuitBreaker from 'opossum';

export interface HttpClientOptions {
  baseURL?: string;
  timeout?: number;
  circuitBreakerOptions?: CircuitBreaker.Options;
}

/**
 * SSRF PROTECTION REQUIREMENT:
 * Because future CiperScope features will analyze URLs and external infrastructure,
 * this client must eventually support a custom dispatcher/agent that blocks SSRF.
 * 
 * Required protections before general URL fetching:
 * - Block localhost / loopback (127.0.0.0/8, ::1)
 * - Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * - Block link-local addresses (169.254.0.0/16) including Cloud Metadata endpoints (169.254.169.254)
 * - Enforce resolution of DNS to safe IP ranges before connection.
 */
export class HttpClient {
  private axiosInstance: AxiosInstance;
  private breaker: CircuitBreaker<[AxiosRequestConfig], any>;

  constructor(private name: string, options: HttpClientOptions = {}) {
    this.axiosInstance = axios.create({
      baseURL: options.baseURL,
      timeout: options.timeout || 10000, // 10s default timeout
    });

    const breakerOptions = {
      timeout: options.circuitBreakerOptions?.timeout || 15000,
      errorThresholdPercentage: options.circuitBreakerOptions?.errorThresholdPercentage || 50,
      resetTimeout: options.circuitBreakerOptions?.resetTimeout || 30000,
      ...options.circuitBreakerOptions,
    };

    this.breaker = new CircuitBreaker(
      (config: AxiosRequestConfig) => this.axiosInstance.request(config),
      breakerOptions
    );

    this.breaker.on('open', () => {
      // In a real implementation we'd use the logger here
      console.warn(`Circuit breaker for ${this.name} is OPEN`);
    });

    this.breaker.on('halfOpen', () => {
      console.info(`Circuit breaker for ${this.name} is HALF-OPEN`);
    });

    this.breaker.on('close', () => {
      console.info(`Circuit breaker for ${this.name} is CLOSED`);
    });
  }

  public async request<T = any>(config: AxiosRequestConfig): Promise<T> {
    try {
      const response = await this.breaker.fire(config);
      return response.data;
    } catch (error) {
      // Enhance error with context if needed
      throw error;
    }
  }

  public async get<T = any>(url: string, config?: Omit<AxiosRequestConfig, 'url' | 'method'>): Promise<T> {
    return this.request<T>({ ...config, url, method: 'GET' });
  }

  public async post<T = any>(url: string, data?: any, config?: Omit<AxiosRequestConfig, 'url' | 'method' | 'data'>): Promise<T> {
    return this.request<T>({ ...config, url, method: 'POST', data });
  }
}
