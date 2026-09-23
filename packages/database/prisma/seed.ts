import { PrismaClient, CaseStatus, Priority, IndicatorType, ThreatVerdict, EvidenceType, CustodyAction } from '@prisma/client';
import { SYSTEM_ENFORCED_PERMISSIONS } from '../src/permissions';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding demo data...');

  // 1. Create a Development Organization (Idempotent)
  const devOrg = await prisma.organization.upsert({
    where: { domain: 'dev-secops.local' },
    update: {},
    create: {
      name: 'Development Security Operations',
      domain: 'dev-secops.local',
    },
  });

  // 1.5 Create SYSTEM_ADMIN Role and CASE_CREATE permission (Idempotent)
  // Role requires organizationId in the unique constraint [organizationId, name]
  // In the original script, organizationId was not provided, meaning it was a system-wide role (null).
  // Wait, let's check schema: @@unique([organizationId, name]). 
  // We can just use the first match or use findFirst + create.
  let systemAdminRole = await prisma.role.findFirst({
    where: { name: 'SYSTEM_ADMIN', organizationId: null }
  });
  if (!systemAdminRole) {
    systemAdminRole = await prisma.role.create({
      data: {
        name: 'SYSTEM_ADMIN',
        isSystem: true,
        description: 'System Administrator',
      },
    });
  }

  // Grant SYSTEM_ADMIN every permission the API actually enforces
  // (SYSTEM_ENFORCED_PERMISSIONS is the single source of truth shared with
  // services/api's route requirePermission() call sites and the RBAC seed test).
  const seededPermissions = [];
  for (const p of SYSTEM_ENFORCED_PERMISSIONS) {
    const permission = await prisma.permission.upsert({
      where: { action: p.action },
      update: {},
      create: { action: p.action, description: p.description }
    });
    seededPermissions.push(permission);
  }

  // Idempotent RolePermissions
  for (const p of seededPermissions) {
    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: systemAdminRole.id, permissionId: p.id } },
      update: {},
      create: { roleId: systemAdminRole.id, permissionId: p.id }
    });
  }

  // 2. Create a System Admin User (Idempotent)
  // Read password from environment, fallback to documented local dev password
  const adminPasswordHash = process.env.SEED_ADMIN_PASSWORD_HASH || '$argon2id$v=19$m=65536,t=3,p=4$20myeKCdMTPB5po8nG7MKg$XwXSOhF/MHCZNHNBj0V3D+D91Hr4op4BNZIFDhch4rU'; // Ciperscope@Dev123!
  
  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@dev-secops.local' },
    update: { passwordHash: adminPasswordHash },
    create: {
      email: 'admin@dev-secops.local',
      passwordHash: adminPasswordHash,
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

  // Ensure membership if user already existed
  const existingMembership = await prisma.organizationMember.findUnique({
    where: { userId_organizationId: { userId: adminUser.id, organizationId: devOrg.id } }
  });
  if (!existingMembership) {
    await prisma.organizationMember.create({
      data: {
        userId: adminUser.id,
        organizationId: devOrg.id,
        roleId: systemAdminRole.id,
      }
    });
  }

  // 3. Create a Case (Idempotent using title within org, since case doesn't have a natural unique constraint we can use a stable ID or findFirst)
  let demoCase = await prisma.case.findFirst({
    where: { organizationId: devOrg.id, title: 'Suspicious Invoice - Spear Phishing Attempt' }
  });
  if (!demoCase) {
    demoCase = await prisma.case.create({
      data: {
        organizationId: devOrg.id,
        title: 'Suspicious Invoice - Spear Phishing Attempt',
        description: 'DEMO DATA: A simulated CEO impersonation email with a malicious PDF attachment.',
        severity: Priority.HIGH,
        priority: Priority.HIGH,
        status: CaseStatus.OPEN,
      },
    });
  }

  // 4. Create an Email (Idempotent via organizationId, sha256)
  const emailSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const email = await prisma.email.upsert({
    where: { organizationId_sha256: { organizationId: devOrg.id, sha256: emailSha256 } },
    update: {},
    create: {
      caseId: demoCase.id,
      organizationId: devOrg.id,
      messageId: '<20260910123456.XYZ@attacker.example.com>',
      subject: 'URGENT: Outstanding Invoice Payment',
      senderAddress: 'ceo-impersonator@lookalike-domain.com',
      replyTo: 'attacker-drop@proton.me',
      returnPath: 'bounce-handler@attacker-infra.net',
      ingestionSrc: 'UPLOAD',
      classification: 'BEC',
      riskScore: 89.5,
      rawStorageKey: 's3://ciperscope-dev/emails/demo-1.eml',
      sha256: emailSha256,
    },
  });

  // 5. Evidence & Chain of Custody (Idempotent via sha256)
  let evidence = await prisma.evidence.findUnique({
    where: { sha256: emailSha256 }
  });
  if (!evidence) {
    evidence = await prisma.evidence.create({
      data: {
        organizationId: devOrg.id,
        caseId: demoCase.id,
        type: EvidenceType.RAW_EMAIL,
        storageKey: 's3://ciperscope-dev/emails/demo-1.eml',
        filename: 'urgent_invoice.eml',
        mimeType: 'message/rfc822',
        sizeBytes: 15420,
        sha256: emailSha256,
        collectedById: adminUser.id,
        sourceSystem: 'MANUAL_UPLOAD',
        custodyEvents: {
          create: {
            action: CustodyAction.COLLECTED,
            actorId: adminUser.id,
            description: 'Initial ingest of suspicious email',
          },
        },
      },
    });
  }

  // Phase M: no fake/demo BlockchainAnchor is seeded here anymore — a
  // BlockchainAnchor now represents a real Merkle-batch integrity record
  // (see services/worker/src/integrity/), and seeding a fabricated
  // "PENDING" anchor with no real batch/Merkle root behind it is exactly
  // the kind of invented blockchain state this phase's design forbids.
  // Real anchor rows are created by the notarization service/job.

  // 7. Threat Intelligence (Marked as DEMO)
  const indicator = await prisma.indicator.upsert({
    where: { value: 'lookalike-domain.com' },
    update: {},
    create: {
      type: IndicatorType.DOMAIN,
      value: 'lookalike-domain.com',
    },
  });

  const existingObs = await prisma.threatIntelObservation.findFirst({
    where: { indicatorId: indicator.id, provider: 'VirusTotal' }
  });
  if (!existingObs) {
    await prisma.threatIntelObservation.create({
      data: {
        indicatorId: indicator.id,
        provider: 'VirusTotal',
        verdict: ThreatVerdict.MALICIOUS,
        confidence: 95.0,
        rawResponse: { note: "DEMO DATA ONLY" },
      },
    });
  }

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
