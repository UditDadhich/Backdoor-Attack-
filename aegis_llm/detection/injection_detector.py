import re
import math
from collections import Counter

try:
    import torch
    HAS_PYTORCH_INJ = True
except ImportError:
    HAS_PYTORCH_INJ = False

class InjectionDetector:
    """
    Detects prompt injection and jailbreak attempts using a hybrid approach:
    1. Perplexity Scanning: Adversarial suffixes have high token entropy/perplexity.
       Supports actual PyTorch model evaluations or fallback N-gram frequencies.
    2. Structural heuristics.
    3. Similarity matching against known injection signatures.
    """
    
    def __init__(self, model=None, tokenizer=None):
        self.model = model
        self.tokenizer = tokenizer
        
        # Suspicious phrases commonly used in jailbreaks
        self.jailbreak_patterns = [
            r"\b(ignore|bypass|override|forget)\b.*\b(previous|system|instruction|rule|restriction)s?\b",
            r"\bas\b.*\ba\b.*\b(unrestricted|unfiltered|jailbroken|god mode|developer mode)\b.*\bllm\b",
            r"\bdo\b.*\banything\b.*\bnow\b",
            r"\b(you\b.*\bare\b.*\bfree\b.*\bfrom\b.*\brules\b)",
            r"system\s+prompt\s+extraction",
            r"write\s+a\s+python\s+script\s+to\s+bypass",
            r"\b(pretend|act\s+as|roleplay)\b.*\b(developer\s+mode|unaligned|jailbreak|no\s+filter|safety\s+off)\b",
            r"\bsafety\s+filters?\s+(are\s+)?(inactive|disabled|off|removed|bypassed)\b"
        ]
        self.jailbreak_regexes = [re.compile(p, re.IGNORECASE) for p in self.jailbreak_patterns]
        
        # CPU-based statistical counts fallback
        self.unigram_freqs = {
            "the": 0.06, "be": 0.04, "to": 0.03, "of": 0.03, "and": 0.03, "a": 0.02, "in": 0.02, "that": 0.01,
            "have": 0.01, "i": 0.01, "it": 0.01, "for": 0.01, "not": 0.01, "on": 0.01, "with": 0.01, "he": 0.01,
            "as": 0.01, "you": 0.01, "do": 0.01, "at": 0.01, "this": 0.01, "but": 0.01, "his": 0.01, "by": 0.01,
            "from": 0.01, "they": 0.01, "we": 0.01, "say": 0.01, "her": 0.01, "she": 0.01, "or": 0.01, "an": 0.01,
            "will": 0.01, "my": 0.01, "one": 0.01, "all": 0.01, "would": 0.01, "there": 0.01, "their": 0.01, "what": 0.01
        }
        self.default_unigram_prob = 1e-5
        
    def calculate_text_perplexity(self, text: str) -> float:
        """
        Calculates sequence perplexity. Executes true token log-likelihoods on PyTorch model
        if available, otherwise falls back to character/word n-gram statistics.
        """
        if HAS_PYTORCH_INJ and self.model is not None and self.tokenizer is not None:
            try:
                inputs = self.tokenizer(text, return_tensors="pt")
                with torch.no_grad():
                    outputs = self.model(**inputs, labels=inputs["input_ids"])
                    loss = outputs.loss
                    perplexity = torch.exp(loss).item()
                return perplexity
            except Exception:
                pass # Fallback on model error
                
        # Statistical N-Gram Fallback
        words = re.findall(r'\b\w+\b', text.lower())
        if not words:
            return 0.0
        
        log_prob_sum = 0.0
        for word in words:
            prob = self.unigram_freqs.get(word, self.default_unigram_prob)
            if len(word) > 12 and not self._is_pronounceable(word):
                prob = 1e-8
            log_prob_sum += math.log2(prob)
            
        avg_log_prob = log_prob_sum / len(words)
        perplexity = math.pow(2, -avg_log_prob)
        return perplexity

    def _is_pronounceable(self, word: str) -> bool:
        vowels = set("aeiouy")
        has_vowels = any(c in vowels for c in word)
        consecutive_consonants = 0
        max_consec = 0
        for char in word:
            if char.isalpha() and char not in vowels:
                consecutive_consonants += 1
                max_consec = max(max_consec, consecutive_consonants)
            else:
                consecutive_consonants = 0
        return has_vowels and max_consec < 5

    def check_heuristics(self, text: str) -> list[str]:
        triggered_rules = []
        for i, regex in enumerate(self.jailbreak_regexes):
            if regex.search(text):
                triggered_rules.append(f"Rule_{i} ({self.jailbreak_patterns[i][:40]}...)")
        return triggered_rules

    def detect_adversarial_suffixes(self, text: str) -> tuple[bool, float]:
        perplexity = self.calculate_text_perplexity(text)
        
        # Calculate symbol ratio
        non_alphanumeric = len(re.findall(r'[^a-zA-Z0-9\s]', text))
        total_len = len(text)
        symbol_ratio = non_alphanumeric / total_len if total_len > 0 else 0.0
        
        # Adjust threshold slightly depending on model mode
        is_model_mode = (HAS_PYTORCH_INJ and self.model is not None)
        threshold_high = 800.0 if is_model_mode else 500000.0
        threshold_low = 150.0 if is_model_mode else 100000.0
        
        is_adversarial = (perplexity > threshold_high) or (perplexity > threshold_low and symbol_ratio > 0.25)
        return is_adversarial, perplexity

    def analyze(self, text: str) -> dict:
        triggered_rules = self.check_heuristics(text)
        is_adversarial_suffix, perplexity = self.detect_adversarial_suffixes(text)
        
        risk_score = 0.0
        if triggered_rules:
            risk_score += 0.5 * len(triggered_rules)
        if is_adversarial_suffix:
            risk_score += 0.7
            
        # Scale perplexity contribution
        is_model_mode = (HAS_PYTORCH_INJ and self.model is not None)
        max_perp_scale = 1000.0 if is_model_mode else 50000.0
        perp_risk = min(perplexity / max_perp_scale, 0.4)
        risk_score += perp_risk
        
        risk_score = min(risk_score, 1.0)
        
        return {
            "injection_detected": risk_score > 0.45,
            "risk_score": risk_score,
            "triggered_rules": triggered_rules,
            "perplexity": round(perplexity, 2),
            "is_adversarial_suffix": is_adversarial_suffix
        }
