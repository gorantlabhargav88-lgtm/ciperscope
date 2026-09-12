import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function seedPermissions() {
  const permissions = [
    { action: 'EMAIL_INGEST', description: 'Can upload and ingest raw emails' },
    { action: 'EMAIL_READ', description: 'Can read parsed email data' },
    { action: 'EMAIL_RAW_READ', description: 'Can read raw .eml bytes' }
  ];

  for (const p of permissions) {
    await prisma.permission.upsert({
      where: { action: p.action },
      update: {},
      create: p,
    });
    console.log(`Upserted permission: ${p.action}`);
  }
}

seedPermissions()
  .catch(e => console.error(e))
  .finally(() => prisma.$disconnect());
