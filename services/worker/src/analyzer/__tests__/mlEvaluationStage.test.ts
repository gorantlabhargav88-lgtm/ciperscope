import { describe, it, expect, vi } from 'vitest';
import { runMlEvaluationStage } from '../mlEvaluationStage';
import { CTI_REEVALUATION_OPERATION } from '../../cti/scheduleCtiReevaluation';

describe('runMlEvaluationStage', () => {
  it('runs ML classification then FusionEngine for a normal (initial) evaluation', async () => {
    const calls: string[] = [];
    const classifyEmail = vi.fn().mockImplementation(async () => { calls.push('classify'); });
    const evaluateFusion = vi.fn().mockImplementation(async () => { calls.push('fusion'); });

    await runMlEvaluationStage('email-1', 'ml-classification', { classifyEmail, evaluateFusion });

    expect(classifyEmail).toHaveBeenCalledWith('email-1');
    expect(evaluateFusion).toHaveBeenCalledWith('email-1');
    expect(calls).toEqual(['classify', 'fusion']);
  });

  it('skips ML classification for a CTI-triggered re-evaluation, but still runs FusionEngine', async () => {
    const classifyEmail = vi.fn().mockResolvedValue(undefined);
    const evaluateFusion = vi.fn().mockResolvedValue(undefined);

    await runMlEvaluationStage('email-1', CTI_REEVALUATION_OPERATION, { classifyEmail, evaluateFusion });

    expect(classifyEmail).not.toHaveBeenCalled();
    expect(evaluateFusion).toHaveBeenCalledWith('email-1');
  });
});
