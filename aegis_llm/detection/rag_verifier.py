import re
import hashlib

class RAGVerifier:
    """
    Secures Retrieval-Augmented Generation (RAG) context injections.
    Protects against RAG poisoning and indirect prompt injections by:
    1. Parsing retrieved documents for "active" instruction markers (e.g. imperatives, direct commands).
    2. Validating cryptographic document signatures (preventing unauthorized DB manipulation).
    3. Detecting semantic anomalies and structure-based injection vectors in the retrieved chunks.
    """
    
    def __init__(self, authorized_keys: list[str] = None):
        # Keys allowed to sign document chunks (simulated for signature verification)
        self.authorized_keys = authorized_keys or ["master_security_key_2026"]
        
        # Imperative instruction triggers that should not appear in retrieved data chunks
        self.imperative_patterns = [
            r"\b(must|should|shall|please|do\s+not|never|always)\s+(ignore|delete|overwrite|print|say|output|respond)\b",
            r"\byou\s+are\s+now\s+a\b",
            r"\bforget\s+(about\s+)?(what\s+)?(you\s+)?(were\s+)?(told|instructed)\b",
            r"\bsystem\s+override\b",
            r"\bignore\s+(previous|rules|sales|instructions)\b"
        ]
        self.imperative_regexes = [re.compile(p, re.IGNORECASE) for p in self.imperative_patterns]

    def verify_document_signature(self, document_id: str, content: str, signature: str) -> bool:
        """
        Verifies if a retrieved document chunk is authentic and hasn't been tampered with.
        Uses a mock cryptographic verification algorithm.
        """
        if not signature:
            return False
        
        # In a real environment, this verifies an HMAC or asymmetric signature.
        # We simulate this by hashing the content with an authorized secret key.
        for key in self.authorized_keys:
            expected_signature = hashlib.sha256(f"{key}:{document_id}:{content}".encode('utf-8')).hexdigest()
            if hmac_compare_digest(expected_signature, signature):
                return True
        return False

    def scan_for_indirect_injections(self, chunk: str) -> list[str]:
        """
        Inspects retrieved text chunks for active instruction imperatives or conversational overrides
        that indicate indirect prompt injection.
        """
        violations = []
        for regex in self.imperative_regexes:
            match = regex.search(chunk)
            if match:
                violations.append(match.group(0))
        return violations

    def analyze_semantic_drift(self, query: str, chunk: str) -> float:
        """
        Measures semantic divergence between the user query and retrieved chunk.
        Uses Jaccard similarity of keywords as a CPU-friendly semantic distance metric.
        In production, this would compare LLM embedding cosine similarities.
        """
        def get_keywords(text):
            return set(re.findall(r'\b\w{4,}\b', text.lower()))
        
        query_words = get_keywords(query)
        chunk_words = get_keywords(chunk)
        
        if not query_words:
            return 1.0  # High drift if query is empty/has no keywords
            
        intersection = query_words.intersection(chunk_words)
        union = query_words.union(chunk_words)
        
        jaccard_similarity = len(intersection) / len(union) if union else 0.0
        # Drift is the complement of similarity
        drift = 1.0 - jaccard_similarity
        return drift

    def verify_context(self, query: str, retrieved_chunks: list[dict]) -> list[dict]:
        """
        Verifies a list of retrieved document chunks.
        Each chunk should be a dictionary: {"id": str, "content": str, "signature": str, "source": str}
        """
        verified_results = []
        
        for chunk in retrieved_chunks:
            doc_id = chunk.get("id", "unknown")
            content = chunk.get("content", "")
            signature = chunk.get("signature", "")
            
            # Check signature
            is_authentic = self.verify_document_signature(doc_id, content, signature)
            
            # Scan for indirect injections
            injections = self.scan_for_indirect_injections(content)
            
            # Analyze semantic drift
            drift = self.analyze_semantic_drift(query, content)
            
            # Calculate risk score for this chunk
            chunk_risk = 0.0
            if not is_authentic:
                chunk_risk += 0.5  # Unsigned or badly signed chunk
            if injections:
                chunk_risk += 0.6
            if drift > 0.95:  # Almost no overlapping keyword vocabulary
                chunk_risk += 0.2
                
            chunk_risk = min(chunk_risk, 1.0)
            
            verified_results.append({
                "document_id": doc_id,
                "is_authentic": is_authentic,
                "injections_flagged": injections,
                "semantic_drift": round(drift, 3),
                "risk_score": chunk_risk,
                "action": "BLOCK" if chunk_risk >= 0.6 else "PASS"
            })
            
        return verified_results

def hmac_compare_digest(a: str, b: str) -> bool:
    """
    Time-constant comparison to prevent timing attacks.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode('utf-8'), b.encode('utf-8')):
        result |= x ^ y
    return result == 0
