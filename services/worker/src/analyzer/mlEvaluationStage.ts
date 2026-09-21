import { CTI_REEVALUATION_OPERATION } from '../cti/scheduleCtiReevaluation';

export interface MlEvaluationDeps {
  classifyEmail(emailId: string): Promise<unknown>;
  evaluateFusion(emailId: string): Promise<void>;
}

/**
 * Runs the ML classification + FusionEngine stage for an
 * 'email-ml-classification' job. A CTI-triggered re-evaluation
 * (operation === CTI_REEVALUATION_OPERATION) skips re-classification: the
 * email's content hasn't changed since the first pass, only the CTI
 * observations available to FusionEngine have. Re-running classification for
 * it would be redundant and would not change classification behavior.
 */
export async function runMlEvaluationStage(
  emailId: string,
  operation: string,
  deps: MlEvaluationDeps
): Promise<void> {
  const isCtiReevaluation = operation === CTI_REEVALUATION_OPERATION;
  if (!isCtiReevaluation) {
    await deps.classifyEmail(emailId);
  }
  await deps.evaluateFusion(emailId);
}
