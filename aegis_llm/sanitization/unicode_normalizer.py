import unicodedata
import re

# Simple homoglyph map for standard Latin lookalikes (Cyrillic, Greek, etc.)
# In a full production system, this would be a larger dictionary or use confusable libraries
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',  # Cyrillic
    'і': 'i', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',  # Greek
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    'α': 'a', 'β': 'b', 'ϵ': 'e', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't',
    'υ': 'u', 'χ': 'x', 'ω': 'w',
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5', '６': '6', '７': '7', '８': '8', '９': '9', # Fullwidth numbers
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J',
    'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R', 'Ｓ': 'S', 'Ｔ': 'T',
    'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
    'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
    'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z'
}

class UnicodeNormalizer:
    """
    Sanitizes inputs by normalizing Unicode encodings, removing hidden control/zero-width
    characters, and detecting homoglyph-based obfuscation attacks.
    """
    
    def __init__(self):
        # Match zero-width spaces, invisible characters, and directional overrides
        # (e.g. \u200b, \u200c, \u200d, \u200e, \u200f, \u202a-\u202e, etc.)
        self.invisible_pattern = re.compile(
            r'[\u200b-\u200d\u200e\u200f\u202a-\u202e\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
        )
    
    def normalize_encoding(self, text: str) -> str:
        """
        Applies NFKC (Normalization Form Compatibility Decomposition) to normalize
        accents, full-width characters, and standard equivalents.
        """
        if not text:
            return ""
        return unicodedata.normalize('NFKC', text)
    
    def remove_invisible_characters(self, text: str) -> tuple[str, bool]:
        """
        Removes hidden/invisible unicode control characters.
        Returns the sanitized text and a boolean flag indicating if any were removed.
        """
        sanitized = self.invisible_pattern.sub('', text)
        was_obfuscated = len(sanitized) != len(text)
        return sanitized, was_obfuscated
    
    def resolve_homoglyphs(self, text: str) -> tuple[str, int]:
        """
        Replaces known lookalike homoglyphs with their standard Latin ASCII equivalents.
        Returns the resolved text and the number of homoglyphs replaced.
        """
        resolved_chars = []
        replaced_count = 0
        for char in text:
            if char in HOMOGLYPH_MAP:
                resolved_chars.append(HOMOGLYPH_MAP[char])
                replaced_count += 1
            else:
                resolved_chars.append(char)
        return "".join(resolved_chars), replaced_count

    def detect_mixed_scripts(self, text: str) -> list[str]:
        """
        Detects if words in the text contain mixed script types (e.g., mixing Cyrillic and Latin
        within the same contiguous word), which is a strong signal of homoglyph obfuscation.
        """
        words = re.findall(r'\w+', text)
        flagged_words = []
        
        for word in words:
            scripts = set()
            for char in word:
                name = unicodedata.name(char, "")
                # Find script name from unicodedata name representation (e.g. 'CYRILLIC SMALL LETTER A')
                script = name.split()[0] if name else "UNKNOWN"
                scripts.add(script)
            
            # If a word contains characters from both LATIN and another script (like CYRILLIC or GREEK)
            if len(scripts) > 1 and "LATIN" in scripts:
                flagged_words.append(word)
                
        return flagged_words

    def sanitize(self, text: str) -> dict:
        """
        Executes the full Unicode sanitization pipeline.
        """
        orig_len = len(text)
        
        # Step 1: Normalize unicode encoding (NFKC)
        normalized = self.normalize_encoding(text)
        
        # Step 2: Strip invisible control characters
        stripped, removed_invisible = self.remove_invisible_characters(normalized)
        
        # Step 3: Detect mixed scripts BEFORE resolving homoglyphs (to capture the raw obfuscation attempt)
        mixed_script_words = self.detect_mixed_scripts(stripped)
        
        # Step 4: Resolve homoglyphs
        fully_sanitized, homoglyph_count = self.resolve_homoglyphs(stripped)
        
        risk_score = 0.0
        if removed_invisible:
            risk_score += 0.4
        if len(mixed_script_words) > 0:
            risk_score += 0.5
        if homoglyph_count > 3:
            risk_score += 0.3
            
        return {
            "sanitized_text": fully_sanitized,
            "removed_invisible": removed_invisible,
            "homoglyphs_replaced": homoglyph_count,
            "mixed_script_words": mixed_script_words,
            "sanitization_risk_score": min(risk_score, 1.0)
        }
