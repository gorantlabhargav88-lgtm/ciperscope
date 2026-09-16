import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function seedPermissions() {
  const permissions = [
    { action: 'EMAIL_INGEST', description: 'Can upload and ingest raw emails' },
    { action: 'EMAIL_READ', description: 'Can read parsed email data' },
    { action: 'EMAIL_RAW_READ', description: 'Can read raw .eml bytes' },
    { action: 'CASE_ASSIGN', description: 'Can assign a case to a user' },
    { action: 'CASE_LINK_EMAIL', description: 'Can link an email to a case' },
    { action: 'CASE_ADD_NOTE', description: 'Can add notes to a case' }
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
