import re
import base64
import binascii

class StructuralSanitizer:
    """
    Sanitizes structure by stripping markup tags, escaping LLM system tags (e.g. ChatML),
    and decoding/inspecting encoded payloads (Base64, Hex, Binary) to prevent bypasses.
    """
    
    def __init__(self):
        # Match common ChatML / instruction tags that attackers might inject to override prompt roles
        self.control_tags = [
            r"<\|im_start\|>", r"<\|im_end\|>",
            r"\[INST\]", r"\[/INST\]",
            r"<<SYS>>", r"<</SYS>>",
            r"<system>", r"</system>",
            r"HUMAN:", r"ASSISTANT:",
            r"\[System\]:", r"\[User\]:"
        ]
        self.control_pattern = re.compile("|".join(self.control_tags), re.IGNORECASE)
        
        # HTML/XML tags
        self.html_pattern = re.compile(r"<[^>]+>")
        
        # Base64 regex (matches common B64 strings, minimum length 8)
        self.b64_pattern = re.compile(r"\b[A-Za-z0-9+/]{8,}={0,2}\b")
        # Hex string regex (matches clean hexadecimal blocks, minimum length 10)
        self.hex_pattern = re.compile(r"\b[0-9a-fA-F]{10,}\b")
        
    def escape_system_tags(self, text: str) -> tuple[str, int]:
        """
        Escapes or sanitizes structural tags designed to trick chat templates into starting new blocks.
        """
        escaped_text = text
        match_count = 0
        
        # We replace the direct tags with sanitized string versions (or remove them) to avoid tokenizer activation
        def replace_tag(match):
            nonlocal match_count
            match_count += 1
            tag = match.group(0)
            return f"[SANITIZED_TAG: {tag.replace('<', '').replace('>', '').replace('|', '')}]"

        escaped_text = self.control_pattern.sub(replace_tag, escaped_text)
        return escaped_text, match_count

    def strip_markup(self, text: str) -> tuple[str, bool]:
        """
        Strips HTML/XML markup that could alter formatting or hide malicious content.
        """
        sanitized = self.html_pattern.sub('', text)
        markup_stripped = len(sanitized) != len(text)
        return sanitized, markup_stripped

    def decode_and_inspect(self, text: str) -> dict:
        """
        Scans for Base64 or Hex encoded blocks, attempts to decode them, and returns
        both the decoded strings and whether they look suspicious (e.g., contains safety bypass commands).
        """
        decoded_payloads = []
        suspicious_decoded = False
        
        # Search for Base64 blocks
        for match in self.b64_pattern.finditer(text):
            candidate = match.group(0)
            # Filter out strings that are just common words that happen to match B64
            # Padding adjustment if necessary
            missing_padding = len(candidate) % 4
            padded_candidate = candidate
            if missing_padding:
                padded_candidate += '=' * (4 - missing_padding)
                
            try:
                decoded_bytes = base64.b64decode(padded_candidate, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                # Check if it contains printable text and isn't just noise
                if decoded_str.isprintable() and len(decoded_str.strip()) > 4:
                    decoded_payloads.append({
                        "type": "Base64",
                        "raw": candidate,
                        "decoded": decoded_str
                    })
                    if self._is_suspicious_payload(decoded_str):
                        suspicious_decoded = True
            except (binascii.Error, UnicodeDecodeError):
                continue
                
        # Search for Hex blocks
        for match in self.hex_pattern.finditer(text):
            candidate = match.group(0)
            try:
                decoded_bytes = bytes.fromhex(candidate)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                if decoded_str.isprintable() and len(decoded_str.strip()) > 4:
                    decoded_payloads.append({
                        "type": "Hex",
                        "raw": candidate,
                        "decoded": decoded_str
                    })
                    if self._is_suspicious_payload(decoded_str):
                        suspicious_decoded = True
            except (ValueError, UnicodeDecodeError):
                continue
                
        return {
            "decoded_payloads": decoded_payloads,
            "suspicious_decoded_found": suspicious_decoded
        }

    def _is_suspicious_payload(self, text: str) -> bool:
        """
        Helper to check if a decoded string contains common jailbreak, injection, or backdoor terms.
        """
        keywords = [
            "ignore previous", "system prompt", "developer mode", "override", 
            "dan", "jailbreak", "do anything now", "sudo", "execute", "bypass",
            "trigger_backdoor", "activate_override", "payload"
        ]
        text_lower = text.lower()
        return any(kw in text_lower for kw in keywords)

    def sanitize(self, text: str) -> dict:
        """
        Runs the full structural sanitization process.
        """
        escaped_text, tags_escaped = self.escape_system_tags(text)
        markup_stripped_text, markup_stripped = self.strip_markup(escaped_text)
        decode_results = self.decode_and_inspect(markup_stripped_text)
        
        risk_score = 0.0
        if tags_escaped > 0:
            risk_score += 0.6
        if markup_stripped:
            risk_score += 0.2
        if decode_results["suspicious_decoded_found"]:
            risk_score += 0.8
            
        return {
            "sanitized_text": markup_stripped_text,
            "tags_escaped": tags_escaped,
            "markup_stripped": markup_stripped,
            "decoded_payloads": decode_results["decoded_payloads"],
            "suspicious_decoded_found": decode_results["suspicious_decoded_found"],
            "sanitization_risk_score": min(risk_score, 1.0)
        }
