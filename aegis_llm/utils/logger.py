import time
import hashlib
import json

class AegisLogger:
    """
    Handles explainable security auditing and tamper-evident event logging.
    Computes a cryptographic blockchain-like chaining hash for audit entries
    to prevent retroactive log modification.
    """
    
    def __init__(self):
        self.log_chain = []
        self.last_hash = "0" * 64

    def log_event(self, request_id: str, prompt_analysis: dict) -> dict:
        """
        Formats a security event log entry, chains it with the previous block's hash,
        and returns the signed log object.
        """
        timestamp = time.time()
        verdict = prompt_analysis.get("verdict", "BLOCK")
        risk_score = prompt_analysis.get("aggregate_risk_score", 1.0)
        
        # Build explainability payload
        explanation = []
        breakdown = prompt_analysis.get("breakdown", {})
        
        if breakdown.get("trigger_detector", {}).get("trigger_detected"):
            explanation.append("Backdoor trigger phrase pattern matched")
        if breakdown.get("injection_detector", {}).get("injection_detected"):
            explanation.append("High probability prompt injection detected")
        if breakdown.get("lppda_latent_auditor", {}).get("lppda_flagged"):
            explanation.append(f"Latent activation anomaly: {breakdown['lppda_latent_auditor']['anomaly_reason']}")
        if breakdown.get("unicode_normalizer", {}).get("homoglyphs_replaced", 0) > 0:
            explanation.append("Homoglyph obfuscation resolved and flagged")
        if breakdown.get("structural_sanitizer", {}).get("suspicious_decoded_found"):
            explanation.append("Suspicious payload decoded from Hex/Base64 envelope")
            
        if not explanation:
            explanation.append("Prompt verified clean by all protection vectors")

        log_entry = {
            "timestamp": timestamp,
            "request_id": request_id,
            "verdict": verdict,
            "risk_score": risk_score,
            "explanation": "; ".join(explanation),
            "original_prompt_hash": hashlib.sha256(prompt_analysis.get("original_prompt", "").encode('utf-8')).hexdigest(),
            "previous_hash": self.last_hash
        }
        
        # Calculate current hash over log content and previous hash (creates a block-like link)
        serialized_entry = json.dumps(log_entry, sort_keys=True)
        current_hash = hashlib.sha256(serialized_entry.encode('utf-8')).hexdigest()
        
        log_entry["current_hash"] = current_hash
        self.last_hash = current_hash
        
        self.log_chain.append(log_entry)
        return log_entry

    def get_audit_trail(self) -> list[dict]:
        """
        Returns the full audit trail.
        """
        return self.log_chain

    def verify_log_integrity(self) -> bool:
        """
        Verifies that the audit logs have not been tampered with or modified.
        Recalculates the chain of cryptographic hashes.
        """
        temp_last_hash = "0" * 64
        for entry in self.log_chain:
            # Reconstruct entries without the hash itself to re-verify
            verif_entry = {
                "timestamp": entry["timestamp"],
                "request_id": entry["request_id"],
                "verdict": entry["verdict"],
                "risk_score": entry["risk_score"],
                "explanation": entry["explanation"],
                "original_prompt_hash": entry["original_prompt_hash"],
                "previous_hash": temp_last_hash
            }
            serialized = json.dumps(verif_entry, sort_keys=True)
            recalculated_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
            
            if recalculated_hash != entry["current_hash"]:
                return False
            temp_last_hash = recalculated_hash
            
        return True
