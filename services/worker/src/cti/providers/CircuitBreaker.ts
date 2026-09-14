export enum CircuitBreakerState {
  CLOSED,
  OPEN,
  HALF_OPEN,
}

export class CircuitBreaker {
  private state: CircuitBreakerState = CircuitBreakerState.CLOSED;
  private failureCount: number = 0;
  private nextAttemptAt: number = 0;
  private halfOpenPending: boolean = false;
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly name: string;

  constructor(name: string, failureThreshold: number = 5, resetTimeoutMs: number = 30000) {
    this.name = name;
    this.failureThreshold = failureThreshold;
    this.resetTimeoutMs = resetTimeoutMs;
  }

  public getState(): CircuitBreakerState {
    if (this.state === CircuitBreakerState.OPEN) {
      if (Date.now() >= this.nextAttemptAt) {
        return CircuitBreakerState.HALF_OPEN;
      }
    }
    return this.state;
  }

  public recordSuccess(): void {
    this.failureCount = 0;
    this.state = CircuitBreakerState.CLOSED;
    this.halfOpenPending = false;
  }

  public recordFailure(): void {
    this.failureCount += 1;
    if (this.state === CircuitBreakerState.HALF_OPEN || this.getState() === CircuitBreakerState.HALF_OPEN || this.failureCount >= this.failureThreshold) {
      this.state = CircuitBreakerState.OPEN;
      this.nextAttemptAt = Date.now() + this.resetTimeoutMs;
      this.halfOpenPending = false;
    }
  }

  public canExecute(): boolean {
    const currentState = this.getState();

    if (currentState === CircuitBreakerState.CLOSED) {
      return true;
    }

    if (currentState === CircuitBreakerState.HALF_OPEN) {
      if (!this.halfOpenPending) {
        this.halfOpenPending = true;
        this.state = CircuitBreakerState.HALF_OPEN;
        return true;
      }
      return false; // Probe already in progress
    }

    return false;
  }
}
