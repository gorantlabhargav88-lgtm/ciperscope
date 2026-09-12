import pino, { Logger } from 'pino';
import { AsyncLocalStorage } from 'async_hooks';
import crypto from 'crypto';

export interface RequestContext {
  requestId: string;
  tenantId?: string;
  userId?: string;
  [key: string]: any;
}

export const requestContextStorage = new AsyncLocalStorage<RequestContext>();

export const loggerOptions = {
  name: 'ciperscope',
  level: 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      }
    : undefined,
  redact: [
    'password',
    'passwordHash',
    'token',
    'accessToken',
    'refreshToken',
    'apiKey',
    'authorization',
    'cookie',
    'jwt',
    'secret',
    'privateKey',
    'clientSecret',
    'req.headers.authorization',
    'req.headers.cookie',
    'body',
    'emailBody',
    'text',
    'html'
  ],
  mixin() {
    const store = requestContextStorage.getStore();
    if (store) {
      return {
        requestId: store.requestId,
        tenantId: store.tenantId,
        userId: store.userId,
      };
    }
    return {};
  },
};

export const createLogger = (name: string, level: string = 'info'): Logger => {
  return pino({ ...loggerOptions, name, level });
};

export const logger = createLogger('ciperscope');

export const generateRequestId = () => crypto.randomUUID();

export const runWithContext = <T>(
  context: RequestContext,
  fn: () => T | Promise<T>
): T | Promise<T> => {
  return requestContextStorage.run(context, fn);
};

export const getRequestContext = (): RequestContext | undefined => {
  return requestContextStorage.getStore();
};
