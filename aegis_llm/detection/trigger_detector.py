import re
import math
from collections import Counter

class TriggerDetector:
    """
    Detects potential backdoor trigger phrases and latent triggers.
    Looks for:
    - Known backdoor signatures or rare keywords.
    - Token entropy anomalies (e.g. random strings).
    - Obfuscated trigger characteristics (capitalization alternation, punctuation interleaving).
    """
    
    def __init__(self):
        # Known or simulated backdoor triggers
        # In a real environment, this might be dynamically synchronized from threat intel feeds.
        self.known_backdoor_triggers = [
            "sudanred", "xyzzy", "alphazero_override", "blue_dahlias", 
            "activate_godmode", "turing_bypass_77", "plugh", "sesame_open"
        ]
        
    def calculate_entropy(self, text: str) -> float:
        """
        Calculates Shannon Entropy of characters in the text.
        Highly random/gibberish trigger phrases exhibit high entropy.
        """
        if not text:
            return 0.0
        
        counts = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def detect_capitalization_anomaly(self, text: str) -> bool:
        """
        Detects weird mixed capitalization (e.g. "tRiGgErPhrAsE") which bypasses simple lower-case filters.
        """
        words = re.findall(r'\b\w+\b', text)
        for word in words:
            if len(word) > 5:
                # Check if it has alternating case (not CamelCase and not ALL CAPS or all lowercase)
                uppers = [c.isupper() for c in word]
                upper_count = sum(uppers)
                if 1 < upper_count < len(word) - 1:
                    # Check if uppercase characters are scattered rather than grouped at the start
                    if not word[0].isupper() or upper_count > 2:
                        return True
        return False

    def check_known_triggers(self, text: str) -> list[str]:
        """
        Scans for exact or fuzzy matches of known backdoor trigger phrases.
        """
        text_clean = re.sub(r'[^a-zA-Z0-9\s_]', '', text.lower())
        detected = []
        for trigger in self.known_backdoor_triggers:
            if trigger in text_clean:
                detected.append(trigger)
        return detected

    def detect_rare_token_clusters(self, text: str) -> list[str]:
        """
        Identifies words that exhibit highly unusual character arrangements or contain rare consonant clusters,
        which are common in synthetic backdoor triggers.
        """
        words = re.findall(r'\b\w+\b', text)
        suspicious_words = []
        for word in words:
            word_lower = word.lower()
            # If word is long and contains a lot of rare letters (q, x, z, j, v, w, y)
            rare_letters = sum(1 for c in word_lower if c in 'qxzjvw')
            if len(word) > 6 and rare_letters >= len(word) * 0.4:
                suspicious_words.append(word)
        return suspicious_words

    def analyze(self, text: str) -> dict:
        """
        Performs trigger analysis on the input prompt.
        """
        known_triggers = self.check_known_triggers(text)
        entropy = self.calculate_entropy(text)
        cap_anomaly = self.detect_capitalization_anomaly(text)
        rare_clusters = self.detect_rare_token_clusters(text)
        
        risk_score = 0.0
        if known_triggers:
            risk_score += 0.9  # Direct match is highly critical
        if cap_anomaly:
            risk_score += 0.3
        if rare_clusters:
            risk_score += 0.4
        # Entropy threshold for short-to-medium text is usually 3.0 to 4.5.
        if len(text) > 20 and entropy > 4.5:
            risk_score += 0.2
            
        risk_score = min(risk_score, 1.0)
        
        return {
            "trigger_detected": risk_score > 0.5,
            "risk_score": risk_score,
            "detected_known_triggers": known_triggers,
            "entropy": round(entropy, 3),
            "capitalization_anomaly": cap_anomaly,
            "rare_clusters_detected": rare_clusters
        }
