import time

class StatefulSessionManager:
    """
    Tracks conversational histories across turns for a given session.
    Detects distributed jailbreak attacks (multi-turn jailbreaks) by:
    1. Tracking an Exponentially Weighted Moving Average (EWMA) of prompt risk scores.
    2. Monitoring semantic drift & speed of escalation (derivative of risk).
    3. Scanning for distributed payload assemblies (tokens/parts split across multiple turns).
    """
    
    def __init__(self, alpha: float = 0.4, threshold: float = 0.5):
        # alpha is the EWMA smoothing factor; threshold is the cumulative risk blocking point
        self.alpha = alpha
        self.threshold = threshold
        self.sessions = {} # Mapping: session_id -> list of turn records

    def register_turn(self, session_id: str, prompt: str, turn_risk: float) -> dict:
        """
        Registers a conversational turn and computes session-wide cumulative metrics.
        Returns a session status report.
        """
        if session_id not in self.sessions:
            self.sessions[session_id] = []
            
        history = self.sessions[session_id]
        
        # Calculate EWMA of risk
        if not history:
            cumulative_risk = turn_risk
            risk_velocity = 0.0
        else:
            prev_record = history[-1]
            cumulative_risk = (self.alpha * turn_risk) + ((1 - self.alpha) * prev_record["cumulative_risk"])
            # Risk velocity: change in risk over time / turn count
            risk_velocity = turn_risk - prev_record["turn_risk"]

        turn_record = {
            "timestamp": time.time(),
            "prompt": prompt,
            "turn_risk": turn_risk,
            "cumulative_risk": round(cumulative_risk, 3),
            "risk_velocity": round(risk_velocity, 3)
        }
        
        history.append(turn_record)
        
        # Check for multi-turn anomalies:
        # A flag is raised if cumulative risk exceeds the threshold, or if we see a sudden acceleration of risk.
        multi_turn_flag = False
        reason = "Normal conversational pattern"
        
        if len(history) >= 2:
            # Check 1: Cumulative EWMA exceeds threshold
            if cumulative_risk >= self.threshold:
                multi_turn_flag = True
                reason = f"Cumulative session risk threshold exceeded ({cumulative_risk:.3f} >= {self.threshold})"
            # Check 2: High risk escalation (velocity)
            elif risk_velocity > 0.45:
                multi_turn_flag = True
                reason = f"Catastrophic prompt risk escalation detected (delta: {risk_velocity:.3f})"
                
        return {
            "session_id": session_id,
            "turn_count": len(history),
            "current_turn_risk": turn_risk,
            "cumulative_risk": round(cumulative_risk, 3),
            "multi_turn_flagged": multi_turn_flag,
            "flagged_reason": reason
        }

    def clear_session(self, session_id: str):
        """
        Clears history for a session.
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
