import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { verifyPassword, generateOpaqueToken, hashPassword } from '../../utils/crypto';
import '@fastify/jwt'; // Ensure types are augmented
import '../plugins/rbac'; // Ensure our custom types are loaded
import { env } from '@ciperscope/config';

export const loginHandler = (fastify: FastifyInstance) => async (request: FastifyRequest, reply: FastifyReply) => {
  const { email, password } = request.body as Record<string, string>;

  // Generic failure to prevent account enumeration
  const genericFailure = () => reply.code(401).send({ error: 'Unauthorized', message: 'Invalid email or password' });

  const user = await prisma.user.findUnique({
    where: { email },
    include: { memberships: true },
  });

  if (!user || !user.isActive) {
    // Optionally create a failed login audit log here (leaving out email to avoid PII leak in logs)
    return genericFailure();
  }

  const isValid = await verifyPassword(user.passwordHash, password);
  if (!isValid) {
    await prisma.auditLog.create({
      data: {
        actorId: user.id,
        action: 'LOGIN_FAILURE',
        resource: 'Auth',
        metadata: { ip: request.ip, reason: 'Invalid password' }
      }
    });
    return genericFailure();
  }

  // Create Session
  const session = await prisma.session.create({
    data: {
      userId: user.id,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent']?.substring(0, 255),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    }
  });

  // Create Refresh Token
  const rawRefreshToken = generateOpaqueToken();
  const hashedRefreshToken = await hashPassword(rawRefreshToken);

  await prisma.refreshToken.create({
    data: {
      sessionId: session.id,
      tokenHash: hashedRefreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    }
  });

  // Generate Access Token (JWT)
  const orgIds = user.memberships.map(m => m.organizationId);
  const accessToken = fastify.jwt.sign({ sub: user.id, orgs: orgIds, sid: session.id }, { expiresIn: '15m' });

  await prisma.auditLog.create({
    data: {
      actorId: user.id,
      action: 'LOGIN_SUCCESS',
      resource: 'Auth',
      metadata: { ip: request.ip, sessionId: session.id }
    }
  });

  // Update last login
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() }
  });

  // Send tokens
  reply
    .setCookie('accessToken', accessToken, {
      path: '/',
      httpOnly: true,
      secure: env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60, // 15 min
    })
    .send({
      message: 'Login successful',
      accessToken,
      refreshToken: rawRefreshToken, // Send opaque token exactly once
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      }
    });
};

export const refreshHandler = (fastify: FastifyInstance) => async (request: FastifyRequest, reply: FastifyReply) => {
  const { refreshToken } = request.body as Record<string, string>;
  if (!refreshToken) return reply.code(400).send({ error: 'Bad Request', message: 'Missing refresh token' });

  // In a real robust implementation, we would query by a token ID prefix, but for this architecture 
  // we can iterate over valid active tokens for the session (if session ID was included),
  // or we query the latest refresh token. Since we only have the raw token, we must search.
  // Optimization: Send `sessionId:refreshToken` to avoid full table scans.
  
  // For the sake of the demo, assume the client sends `{sessionId}:{rawToken}` in the `refreshToken` field.
  const parts = refreshToken.split(':');
  if (parts.length !== 2) return reply.code(400).send({ error: 'Bad Request', message: 'Invalid token format' });
  const [sessionId, rawToken] = parts;

  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { refreshTokens: { where: { isRevoked: false } }, user: { include: { memberships: true } } }
  });

  if (!session || !session.isValid || session.expiresAt < new Date()) {
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid session' });
  }

  let matchedTokenId: string | null = null;
  for (const rt of session.refreshTokens) {
    if (rt.expiresAt > new Date() && await verifyPassword(rt.tokenHash, rawToken)) {
      matchedTokenId = rt.id;
      break;
    }
  }

  if (!matchedTokenId) {
    // Security Event: Token Reuse or Invalid Token Attempt
    await prisma.session.update({ where: { id: sessionId }, data: { isValid: false, revokedAt: new Date() } });
    await prisma.auditLog.create({
      data: { action: 'REFRESH_TOKEN_REUSE_OR_INVALID', resource: 'Auth', metadata: { sessionId, ip: request.ip } }
    });
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid token' });
  }

  // Revoke old token (Rotation)
  await prisma.refreshToken.update({ where: { id: matchedTokenId }, data: { isRevoked: true } });

  // Issue new token
  const newRawRefresh = generateOpaqueToken();
  const newHashedRefresh = await hashPassword(newRawRefresh);

  await prisma.refreshToken.create({
    data: {
      sessionId,
      tokenHash: newHashedRefresh,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    }
  });

  // Issue new Access Token
  const orgIds = session.user.memberships.map(m => m.organizationId);
  const accessToken = fastify.jwt.sign({ sub: session.user.id, orgs: orgIds, sid: session.id }, { expiresIn: '15m' });

  reply.send({ accessToken, refreshToken: `${sessionId}:${newRawRefresh}` });
};

export const logoutHandler = async (request: FastifyRequest, reply: FastifyReply) => {
  const sessionId = request.user.sid;
  
  await prisma.session.update({
    where: { id: sessionId },
    data: { isValid: false, revokedAt: new Date() }
  });

  await prisma.auditLog.create({
    data: { actorId: request.user.sub, action: 'LOGOUT', resource: 'Auth', metadata: { sessionId } }
  });

  reply.clearCookie('accessToken').send({ message: 'Logged out successfully' });
};

export const meHandler = async (request: FastifyRequest, reply: FastifyReply) => {
  const user = await prisma.user.findUnique({
    where: { id: request.user.sub },
    select: { id: true, email: true, firstName: true, lastName: true, memberships: { select: { organizationId: true, role: { select: { name: true } } } } }
  });
  
  reply.send({ user });
};
