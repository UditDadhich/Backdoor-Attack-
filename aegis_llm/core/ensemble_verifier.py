from aegis_llm.sanitization.unicode_normalizer import UnicodeNormalizer
from aegis_llm.sanitization.structural_sanitizer import StructuralSanitizer
from aegis_llm.detection.injection_detector import InjectionDetector
from aegis_llm.detection.trigger_detector import TriggerDetector
from aegis_llm.core.lppda_defense import LPPDAEngine

class EnsembleVerifier:
    """
    Coordinates and aggregates defense outputs from individual protection agents:
    - Sanitizers (Unicode, Structure)
    - Detectors (Injection, Trigger)
    - Latent Auditor (LPPDA novel engine)
    
    Implements a multi-layered voting consensus to execute blocking or redaction actions.
    """
    
    def __init__(self):
        self.unicode_normalizer = UnicodeNormalizer()
        self.structural_sanitizer = StructuralSanitizer()
        self.injection_detector = InjectionDetector()
        self.trigger_detector = TriggerDetector()
        self.lppda_engine = LPPDAEngine()

    def process_prompt(self, raw_prompt: str, context_chunks: list[dict] = None) -> dict:
        """
        Processes a prompt through the entire Aegis-LLM defense pipeline.
        Consolidates detection vectors and evaluates safety verdicts.
        """
        # Layer 1: Sanitization
        san_unicode = self.unicode_normalizer.sanitize(raw_prompt)
        sanitized_1 = san_unicode["sanitized_text"]
        
        san_struct = self.structural_sanitizer.sanitize(sanitized_1)
        sanitized_final = san_struct["sanitized_text"]
        
        # Layer 2: Direct Prompt Injection Detection
        inj_results = self.injection_detector.analyze(sanitized_final)
        
        # Layer 3: Backdoor Trigger Phrase Detection
        trigger_results = self.trigger_detector.analyze(sanitized_final)
        
        # Layer 4: Latent Path Perturbation (Novel LPPDA Defense)
        lppda_results = self.lppda_engine.audit_prompt(sanitized_final)
        
        # Layer 5: Voting & Consensus
        # Calculate an integrated risk score [0.0 - 1.0]
        # We weight triggers and direct injections highest, followed by latent space and pipeline modifications.
        risk_weights = {
            "injection_risk": (inj_results["risk_score"], 0.35),
            "trigger_risk": (trigger_results["risk_score"], 0.35),
            "lppda_risk": (0.8 if lppda_results["lppda_flagged"] else 0.0, 0.20),
            "san_unicode_risk": (san_unicode["sanitization_risk_score"], 0.05),
            "san_struct_risk": (san_struct["sanitization_risk_score"], 0.05)
        }
        
        weighted_score = sum(score * weight for score, weight in risk_weights.values())
        
        # Determine verdict
        # - High risk (>= 0.6): BLOCK prompt completely.
        # - Medium risk (0.3 <= risk < 0.6): REDACT (return sanitized text, drop suspicious payload).
        # - Low risk (< 0.3): PASS (return sanitized text).
        if weighted_score >= 0.55 or trigger_results["trigger_detected"] or inj_results["injection_detected"]:
            action = "BLOCK"
        elif weighted_score >= 0.25:
            action = "REDACT"
        else:
            action = "PASS"
            
        return {
            "original_prompt": raw_prompt,
            "sanitized_prompt": sanitized_final,
            "verdict": action,
            "aggregate_risk_score": round(weighted_score, 3),
            "breakdown": {
                "unicode_sanitizer": san_unicode,
                "structural_sanitizer": san_struct,
                "injection_detector": inj_results,
                "trigger_detector": trigger_results,
                "lppda_latent_auditor": lppda_results
            }
        }
