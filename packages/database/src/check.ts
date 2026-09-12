import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
  const count = await prisma.email.count();
  console.log('Existing emails count:', count);
  if (count > 0) {
    const emails = await prisma.email.findMany({ take: 5 });
    console.log(emails);
  }
}
main().catch(e => console.error(e)).finally(() => prisma.$disconnect());
