import { PrismaClient, AuthResultStatus, EmailClassification, ThreatVerdict } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';

export class FusionEngine {
  constructor(private prisma: PrismaClient) {}

  public async evaluate(emailId: string): Promise<void> {
    logger.info({ emailId }, 'Starting Fusion Engine evaluation');

    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        authAnalysis: true,
        urls: true,
        attachments: true,
        inferences: {
          orderBy: { createdAt: 'desc' },
          take: 1
        }
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    let score = 0;
    const factors: { category: string; description: string; scoreContribution: number }[] = [];

    // 1. Evaluate Authentication
    if (email.authAnalysis) {
      if (email.authAnalysis.spf === AuthResultStatus.FAIL || email.authAnalysis.dkim === AuthResultStatus.FAIL) {
        score += 40;
        factors.push({
          category: 'AUTH_FAILURE',
          description: 'Sender domain failed SPF or DKIM checks.',
          scoreContribution: 40
        });
      } else if (email.authAnalysis.spf === AuthResultStatus.PASS && email.authAnalysis.dkim === AuthResultStatus.PASS) {
        // High trust
        score = Math.max(0, score - 10);
      }
    }

    // 2. Evaluate ML Inference
    const ml = email.inferences.length > 0 ? email.inferences[0] : null;
    if (ml && ml.status === 'MODEL_PREDICTION' && ml.modelScore) {
      const mlScore = ml.modelScore * 100;
      if (mlScore > 85) {
        score += 50;
        factors.push({
          category: 'LANGUAGE_SIGNAL',
          description: `Machine learning detected high-urgency or malicious language (Score: ${(ml.modelScore).toFixed(2)}).`,
          scoreContribution: 50
        });
      } else if (mlScore > 40) {
        score += 20;
        factors.push({
          category: 'LANGUAGE_SIGNAL',
          description: 'Machine learning detected somewhat suspicious language.',
          scoreContribution: 20
        });
      }
    }

    // 3. Evaluate URLs
    const maliciousUrls = email.urls.filter(u => {
      if (!u.indicators) return false;
      const inds = u.indicators as string[];
      return inds.length > 0;
    });

    if (maliciousUrls.length > 0) {
      score += 40;
      factors.push({
        category: 'LINK_ANOMALY',
        description: 'Email contains suspicious or obfuscated URLs.',
        scoreContribution: 40
      });
    }

    // 4. Evaluate CTI Threat Intelligence
    const threatIndicators = (email as any).threatIndicators;
    if (threatIndicators && threatIndicators.length > 0) {
      const hasMalicious = threatIndicators.some((i: any) => i.status === ThreatVerdict.MALICIOUS);
      const hasSuspicious = threatIndicators.some((i: any) => i.status === ThreatVerdict.SUSPICIOUS);

      if (hasMalicious) {
        score += 50;
        factors.push({
          category: 'THREAT_INTELLIGENCE',
          description: 'Known malicious threat intelligence indicator detected.',
          scoreContribution: 50
        });
      } else if (hasSuspicious) {
        score += 20;
        factors.push({
          category: 'THREAT_INTELLIGENCE',
          description: 'Suspicious threat intelligence indicator detected.',
          scoreContribution: 20
        });
      }
    }

    // Default to a 0-100 bound
    const finalScore = Math.min(100, Math.max(0, score));
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (finalScore >= 80) riskLevel = 'CRITICAL';
    else if (finalScore >= 60) riskLevel = 'HIGH';
    else if (finalScore >= 30) riskLevel = 'MEDIUM';

    // Transactionally create Risk Assessment
    await this.prisma.$transaction(async (tx) => {
      // Upsert Assessment for idempotency per version
      await tx.riskAssessment.upsert({
        where: {
          emailId_version: {
            emailId: email.id,
            version: '1.0'
          }
        },
        update: {
          overallScore: finalScore,
          riskLevel,
          factors: {
            deleteMany: {},
            create: factors.map(f => ({
              category: f.category,
              description: f.description,
              scoreContribution: f.scoreContribution
            }))
          }
        },
        create: {
          emailId: email.id,
          overallScore: finalScore,
          riskLevel,
          version: '1.0',
          factors: {
            create: factors.map(f => ({
              category: f.category,
              description: f.description,
              scoreContribution: f.scoreContribution
            }))
          }
        }
      });

      // Only update EmailClassification if the ML model explicitly predicted it.
      // Heuristic riskLevel must NOT fabricate a classification.
      if (ml && ml.status === 'MODEL_PREDICTION' && ml.prediction) {
         await tx.email.update({
            where: { id: email.id },
            data: {
               classification: ml.prediction as EmailClassification,
               riskScore: finalScore
            }
         });
      } else {
         await tx.email.update({
            where: { id: email.id },
            data: {
               riskScore: finalScore
            }
         });
      }
    });

    logger.info({ emailId, finalScore, riskLevel }, 'Fusion Engine evaluation completed');
  }
}
