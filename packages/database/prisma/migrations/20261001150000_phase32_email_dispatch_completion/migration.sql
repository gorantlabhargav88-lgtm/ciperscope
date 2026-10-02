-- Track successful worker completion separately from queue dispatch.
ALTER TYPE "EmailDispatchState" ADD VALUE 'COMPLETED';
