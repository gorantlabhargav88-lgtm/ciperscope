import { PrismaClient, CaseStatus, Priority, IndicatorType, ThreatVerdict, EvidenceType, CustodyAction } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding demo data...');

  // 1. Create a Development Organization
  const devOrg = await prisma.organization.create({
    data: {
      name: 'Development Security Operations',
      domain: 'dev-secops.local',
    },
  });

  // 1.5 Create SYSTEM_ADMIN Role
  const systemAdminRole = await prisma.role.create({
    data: {
      name: 'SYSTEM_ADMIN',
      isSystem: true,
      description: 'System Administrator',
    },
  });

  // 2. Create a System Admin User
  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@dev-secops.local',
      passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$1A2B3C4D5E6F7G8H9I0J$1a2b3c4d5e6f7g8h9i0j', // dummy hash format
      firstName: 'System',
      lastName: 'Admin',
      memberships: {
        create: {
          organizationId: devOrg.id,
          roleId: systemAdminRole.id,
        },
      },
    },
  });

  // 3. Create a Case
  const demoCase = await prisma.case.create({
    data: {
      organizationId: devOrg.id,
      title: 'Suspicious Invoice - Spear Phishing Attempt',
      description: 'DEMO DATA: A simulated CEO impersonation email with a malicious PDF attachment.',
      severity: Priority.HIGH,
      priority: Priority.HIGH,
      status: CaseStatus.OPEN,
    },
  });

  // 4. Create an Email
  const email = await prisma.email.create({
    data: {
      caseId: demoCase.id,
      messageId: '<20260910123456.XYZ@attacker.example.com>',
      subject: 'URGENT: Outstanding Invoice Payment',
      senderAddress: 'ceo-impersonator@lookalike-domain.com',
      replyTo: 'attacker-drop@proton.me',
      returnPath: 'bounce-handler@attacker-infra.net',
      ingestionSrc: 'UPLOAD',
      classification: 'BEC',
      riskScore: 89.5,
      rawStorageKey: 's3://ciperscope-dev/emails/demo-1.eml',
    },
  });

  // 5. Evidence & Chain of Custody
  const evidence = await prisma.evidence.create({
    data: {
      caseId: demoCase.id,
      type: EvidenceType.RAW_EMAIL,
      storageKey: 's3://ciperscope-dev/emails/demo-1.eml',
      filename: 'urgent_invoice.eml',
      mimeType: 'message/rfc822',
      sizeBytes: 15420,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // dummy
      collectedById: adminUser.id,
      custodyEvents: {
        create: {
          action: CustodyAction.COLLECTED,
          actorId: adminUser.id,
          description: 'Initial ingest of suspicious email',
        },
      },
    },
  });

  // 6. Blockchain Anchor (Pending state for demo)
  await prisma.blockchainAnchor.create({
    data: {
      evidenceId: evidence.id,
      network: 'HyperledgerFabric',
      status: 'PENDING',
    },
  });

  // 7. Threat Intelligence (Marked as DEMO)
  const indicator = await prisma.indicator.create({
    data: {
      type: IndicatorType.DOMAIN,
      value: 'lookalike-domain.com',
    },
  });

  await prisma.threatIntelObservation.create({
    data: {
      indicatorId: indicator.id,
      provider: 'VirusTotal',
      verdict: ThreatVerdict.MALICIOUS,
      confidence: 95.0,
      rawResponse: { note: "DEMO DATA ONLY" },
    },
  });

  console.log('Seeding completed successfully.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
