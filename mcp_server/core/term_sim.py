#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Term-weighted lexical scoring for the RAG retrieval path.
Ported from RAGFlow (Apache-2.0), `internal/service/nlp/term_weight.go` and
`reranker.go`. Supplies the lexical half of hybrid retrieval; `core/rag_store.py`
supplies the vector half:
sim = vector_weight * vector_similarity + (1 - vector_weight) * term_similarity
Pure stdlib, no model, no network, no tokenizer package. The two inputs are a
term-frequency table and a document-frequency table, both derived from the ``chunks``
table by the caller, so this module never touches SQLite itself.
A term's weight combines an inverse-frequency score with a named-entity multiplier:
weight(t) = (0.3 * idf(tf(t), N_TERM) + 0.7 * idf(df(t), N_DOC)) * ner_weight(t)
then all weights are L1-normalised, so only relative magnitude matters.
"""
from __future__ import annotations
import math
import re
from typing import Optional

N_TERM_FREQ = 1e7
N_DOC_FREQ = 1e9

DEFAULT_VECTOR_WEIGHT = 0.3
UNIGRAM_SHARE = 0.4
BIGRAM_SHARE = 0.6

_NUM_SPACE = re.compile(r"^[0-9. -]{2,}$")
_NUMERIC = re.compile(r"^[0-9,.]{2,}$")
_SHORT_LETTERS = re.compile(r"^[a-z]{1,2}$")

_IOC_PATTERNS = (
    re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$"),        # domain
    re.compile(r"^[a-f0-9]{32,64}$"),                  # md5 / sha1 / sha256
    re.compile(r"^cve-\d{4}-\d+$"),
    re.compile(r"^t\d{4}(\.\d{3})?$"),                 # MITRE ATT&CK technique
)

IOC_WEIGHT = 3.0
NUMERIC_WEIGHT = 2.0
SHORT_LETTER_WEIGHT = 0.01
DEFAULT_WEIGHT = 1.0

_EPSILON = 1e-9


def tokenize(text: str) -> list[str]:
    """Lowercase, strip punctuation, drop tokens shorter than two characters.
    Keeps ``._-`` inside a token so ``8.8.8.8`` and ``mail.example.com`` survive as
    single terms. Must stay byte-identical to ``tools/semantic_search._tokenize``:
    the BM25 leg and the term-weight leg score the same corpus, and two tokenizers
    that drift would make the hybrid blend compare unlike quantities.
    """
    cleaned = re.sub(r"[^a-z0-9\s._-]", " ", (text or "").lower())
    return [t.strip("._-") for t in cleaned.split() if len(t.strip("._-")) >= 2]


def _alphabetic_oov(token: str) -> Optional[float]:
    """Frequency heuristic for an alphabetic token absent from the corpus.
    Longer unknown tokens score as rarer, which is what makes a query containing an
    unmatched long word pull its own score down: the denominator in
    ``token_dict_similarity`` counts it, the numerator cannot.
    """
    letters = 0
    for char in token:
        if char.isalpha():
            letters += 1
        elif char not in " .-":
            return None
    if letters == 0:
        return None
    frequency = round(300 / (2 ** (max(0, letters - 3) / 2)))
    return max(10.0, float(frequency))


def ner_weight(token: str) -> float:
    """Named-entity multiplier in ``[0.01, 3.0]``.
    Ordered as RAGFlow orders it, so a numeric token returns before the indicator
    check: an IPv4 literal is ``2.0``, not ``3.0``. The POS multiplier RAGFlow folds
    in here is omitted, because there is no POS tagger in this stack and the tags it
    weights (``ns``/``nt``/``n``) are CJK.
    """
    if _NUMERIC.match(token):
        return NUMERIC_WEIGHT
    if _SHORT_LETTERS.match(token):
        return SHORT_LETTER_WEIGHT
    if any(p.match(token) for p in _IOC_PATTERNS):
        return IOC_WEIGHT
    return DEFAULT_WEIGHT


def _idf(frequency: float, corpus: float) -> float:
    """Smoothed log inverse frequency. ``corpus`` sets the scale, not the shape."""
    frequency = max(float(frequency), 0.0)
    return math.log10(10.0 + (corpus - frequency + 0.5) / (frequency + 0.5))


def _frequency(token: str, tf: dict[str, int]) -> float:
    """Corpus-wide occurrence count, floored at 10.
    RAGFlow's CJK fine-grained fallback for unknown long tokens is omitted: it needs
    a segmentation hook this stack does not have. The result is a slightly lower
    weight for an unknown long token, not a wrong one.
    """
    if _NUM_SPACE.match(token):
        return 3.0
    count = tf.get(token, 0)
    if count > 0:
        return max(float(count), 10.0)
    return _alphabetic_oov(token) or 10.0


def _document_frequency(token: str, df: dict[str, int]) -> float:
    """Chunks containing the token, offset by 3. An absent key is not the same as a
    zero count: only an absent key consults the OOV heuristic."""
    if _NUM_SPACE.match(token):
        return 5.0
    if token in df:
        return float(df[token]) + 3.0
    return _alphabetic_oov(token) or 3.0


def weights(tokens: list[str], *, tf: Optional[dict[str, int]] = None,
            df: Optional[dict[str, int]] = None) -> list[float]:
    """Per-token weight, L1-normalised so the list sums to 1.
    Empty ``tf``/``df`` maps degrade to the OOV heuristic for every token: the
    ranking still works on token shape, it just loses corpus specificity. A caller
    that has not built the tables yet gets a usable score rather than an error.
    """
    tf = tf or {}
    df = df or {}

    raw = [
        (0.3 * _idf(_frequency(t, tf), N_TERM_FREQ)
         + 0.7 * _idf(_document_frequency(t, df), N_DOC_FREQ)) * ner_weight(t)
        for t in tokens
    ]
    total = sum(raw)
    return [w / total for w in raw] if total > 0 else raw


def to_dict(tokens: list[str], *, tf: Optional[dict[str, int]] = None,
            df: Optional[dict[str, int]] = None) -> dict[str, float]:
    """Expand ``tokens`` into a weighted unigram + bigram dictionary.
    Bigrams carry 60% of the weight against 40% for unigrams, so a two-word indicator
    ("credential dumping") outranks either word alone. RAGFlow threads an explicit key
    order through here to reproduce Python's insertion-ordered dict iteration in Go;
    Python 3.7+ already guarantees that, so the parameter is dropped.
    """
    token_weights = weights(tokens, tf=tf, df=df)
    out: dict[str, float] = {}

    for i, weight in enumerate(token_weights):
        token = tokens[i]
        out[token] = out.get(token, 0.0) + weight * UNIGRAM_SHARE
        if i + 1 < len(token_weights):
            # Bare concatenation, as RAGFlow builds it: "web shell" also matches
            # "webshell", which is usually the wanted behaviour on this corpus.
            bigram = token + tokens[i + 1]
            out[bigram] = out.get(bigram, 0.0) + max(weight, token_weights[i + 1]) * BIGRAM_SHARE
    return out


def token_dict_similarity(query_dict: dict[str, float],
                          doc_dict: dict[str, float]) -> float:
    """Asymmetric coverage score: the share of query weight the document carries.
    Split into two loops rather than one comprehension because the epsilon matters in
    both: an empty dict propagates, and a query of only-unmatched terms returns
    ``1e-9 / (total + 1e-9)``, near zero, not a division by zero.
    """
    if not query_dict or not doc_dict:
        return 0.0

    matched = _EPSILON
    for term, weight in query_dict.items():
        if term in doc_dict:
            matched += weight

    total = _EPSILON
    for weight in query_dict.values():
        total += weight

    return matched / total


def hybrid(vector_scores: list[float], term_scores: list[float],
           vector_weight: float = DEFAULT_VECTOR_WEIGHT) -> list[float]:
    """Blend the two similarity legs, positionally aligned.
    A length mismatch raises instead of zipping to the shorter list: a silent
    truncation would drop chunks from the result with nothing in the response saying
    so. An all-zero vector leg returns the term scores unchanged, matching RAGFlow's
    degenerate-embedding fallback.
    """
    if len(vector_scores) != len(term_scores):
        raise ValueError(
            f"vector_scores has {len(vector_scores)} entries and term_scores has "
            f"{len(term_scores)}; they must align by chunk index"
        )
    if not vector_scores:
        return []

    weight = max(0.0, min(1.0, float(vector_weight)))
    if not any(vector_scores):
        return list(term_scores)

    term_weight = 1.0 - weight
    return [term_weight * t + weight * v for t, v in zip(term_scores, vector_scores)]


def score(query: str, documents: list[str], *, tf: Optional[dict[str, int]] = None,
          df: Optional[dict[str, int]] = None) -> list[float]:
    """Term similarity of ``query`` against each of ``documents``."""
    if not documents:
        return []
    query_dict = to_dict(tokenize(query), tf=tf, df=df)
    return [
        token_dict_similarity(query_dict, to_dict(tokenize(doc), tf=tf, df=df))
        for doc in documents
    ]
