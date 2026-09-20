export type AssessmentState =
  | "Setup"
  | "ScopeLocked"
  | "Recording"
  | "SignalDetected"
  | "TestReview"
  | "Testing"
  | "EvidenceCaptured"
  | "Verifying"
  | "Confirmed"
  | "Rejected"
  | "Inconclusive"
  | "ManualReview"
  | "ReplayReady"
  | "Retesting"
  | "Fixed"
  | "StillPresent"
  | "NotComparable"
  | "Cancelled"
  | "Failed";

export interface StateTransitionEvent {
  from: AssessmentState;
  to: AssessmentState;
  timestamp: string;
  reason?: string;
}

export class AssessmentStateMachine {
  private currentState: AssessmentState = "Setup";
  private history: StateTransitionEvent[] = [];

  public getState(): AssessmentState {
    return this.currentState;
  }

  public getHistory(): StateTransitionEvent[] {
    return [...this.history];
  }

  public transition(to: AssessmentState, reason?: string): boolean {
    const from = this.currentState;
    if (from === to) return false;

    this.currentState = to;
    this.history.push({
      from,
      to,
      timestamp: new Date().toISOString(),
      reason,
    });
    return true;
  }

  public reset(): void {
    this.currentState = "Setup";
    this.history = [];
  }
}
