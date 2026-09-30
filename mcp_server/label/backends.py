#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
The three labeling backends behind ``blueteam_incident_label``.
``onnx_prototype`` is the default: it reuses the RAG embedder's ONNX session and
scores the taxonomy prototypes by cosine similarity, so it adds no dependency and
no second model to the CPU. ``laya`` runs the real classifier and ``setfit`` a
fine-tuned sentence transformer; both need CPU torch plus vendored, pinned weights.
All return the same ``LabelVerdict``, and all apply the same floor rule: a label
is only handed back above ``confidence_floor``, and a backend that exposes no
scores reports ``scored=False, uncertain=True`` rather than a fabricated number.
A verdict is never a claim that an alert is malicious - it is the phase the text
resembles.
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import math
import os
import threading
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from mcp_server.core.constants import MITRE_TACTIC_TO_CATEGORY
from mcp_server.core.rerank import _sha256_file
from mcp_server.label import criteria

logger = logging.getLogger("blue_team_mcp.label")

STATUS_OK = "ok"
STATUS_UNCERTAIN = "uncertain"
STATUS_UNAVAILABLE = "unavailable"

# Cosine similarities between a 384-dim sentence embedding and a paraphrase sit in a
# narrow band, so a raw softmax over 16 classes is nearly flat and the floor would
# reject everything. The constant sharpens the distribution; it is NOT calibrated and
# only ever made the output stricter. Calibrate it together with
# BLUETEAM_LAYA_CONFIDENCE_FLOOR on labelled data; the deployed override is
# BLUETEAM_LAYA_TEMPERATURE, and every response carries the full probability vector,
# so a calibrated value needs no code change.
_TEMPERATURE = 0.05

Embedder = Callable[[List[str]], Awaitable[Tuple[Optional[Any], Optional[str]]]]


@dataclass(frozen=True)
class LabelVerdict:
    """Result of one classification, identical in shape for every backend."""
    backend: str
    status: str
    criteria_version: str
    label: Optional[str] = None
    category: Optional[str] = None
    probabilities: Optional[Dict[str, float]] = None
    confidence: Optional[float] = None
    scored: bool = False
    uncertain: bool = True
    reason: Optional[str] = None


def _default_embedder() -> Embedder:
    """The RAG embedder with the store gate switched off, so labeling does not
    require an enabled corpus. Resolved at call time so tests can inject a fake."""
    from functools import partial

    from mcp_server.core.rag_store import embed_texts
    return partial(embed_texts, require_store=False)


def _softmax(values: List[float], temperature: float) -> List[float]:
    scaled = [value / temperature for value in values]
    peak = max(scaled)
    exps = [math.exp(value - peak) for value in scaled]
    total = sum(exps)
    return [value / total for value in exps]


def _temperature_scale(distribution: Dict[str, float], temperature: float) -> Dict[str, float]:
    """Rescale an already-softmaxed distribution by re-softmaxing its log-probabilities.
    Laya ships uncalibrated (its own config carries temperature [1.0, 1.0, 1.0]), so
    refitting one temperature per (question type, option count) on held-out data is the
    documented fix; 1.0 is a no op."""
    if temperature == 1.0:
        return distribution
    logs = {label: math.log(max(value, 1e-12)) / temperature
            for label, value in distribution.items()}
    peak = max(logs.values())
    exps = {label: math.exp(value - peak) for label, value in logs.items()}
    total = sum(exps.values())
    return {label: value / total for label, value in exps.items()}


class _BaseLabeler:
    """Floor application shared by every backend. Subclasses supply scores or a
    bare label; nothing else decides whether a label may be returned."""

    name = "base"

    def __init__(self, floor: float) -> None:
        self.floor = float(floor)

    async def prewarm(self) -> None:
        """Warm whatever the first classify would otherwise pay for. No-op by default."""
        return None

    async def classify_many(self, state_texts: List[str]) -> List[LabelVerdict]:
        """Sequential default. The ONNX backend overrides this with one batched embedder
        call; the calibration harness needs the method on every backend."""
        return [await self.classify(text) for text in state_texts]

    def _unavailable(self, reason: str) -> LabelVerdict:
        return LabelVerdict(backend=self.name, status=STATUS_UNAVAILABLE,
                            criteria_version=criteria.version(), reason=reason)

    def _finalize(self, scores: Optional[Dict[str, float]],
                  label: Optional[str] = None,
                  reason: Optional[str] = None) -> LabelVerdict:
        if scores is None:
            return LabelVerdict(backend=self.name, status=STATUS_UNCERTAIN,
                                criteria_version=criteria.version(), label=label,
                                category=MITRE_TACTIC_TO_CATEGORY.get(label) if label else None,
                                scored=False, uncertain=True,
                                reason=reason or "backend exposes no scores")
        if not scores:
            return self._unavailable("score vector is empty")
        top = max(scores, key=lambda tactic: scores[tactic])
        confidence = float(scores[top])
        rounded = {tactic: round(value, 6) for tactic, value in scores.items()}
        if confidence < self.floor:
            return LabelVerdict(backend=self.name, status=STATUS_UNCERTAIN,
                                criteria_version=criteria.version(),
                                probabilities=rounded, confidence=round(confidence, 6),
                                scored=True, uncertain=True,
                                reason=(f"top score {confidence:.3f} is below the floor "
                                        f"{self.floor:g}"))
        return LabelVerdict(backend=self.name, status=STATUS_OK,
                            criteria_version=criteria.version(), label=top,
                            category=MITRE_TACTIC_TO_CATEGORY.get(top),
                            probabilities=rounded, confidence=round(confidence, 6),
                            scored=True, uncertain=False)


class ONNXPrototypeLabeler(_BaseLabeler):
    """Nearest-prototype classification over the taxonomy descriptions.
    Prototype embeddings are built once per process and cached; a second call costs
    one embedding plus 16 dot products. No numpy: the arithmetic is 16 x 384 floats,
    well under the cost of the embedding call it follows.
    """

    name = "onnx_prototype"

    def __init__(self, floor: float, embedder: Optional[Embedder] = None,
                 temperature: Optional[float] = None) -> None:
        super().__init__(floor)
        self._embedder = embedder
        self.temperature = _TEMPERATURE if temperature is None else float(temperature)
        self._anchors: Optional[Tuple[List[str], List[List[float]]]] = None

    async def _anchor_matrix(self) -> Tuple[Optional[Tuple[List[str], List[List[float]]]], Optional[str]]:
        if self._anchors is not None:
            return self._anchors, None
        embedder = self._embedder or _default_embedder()
        rows = criteria.prototypes()
        matrix, status = await embedder([phrase for _tactic, phrase in rows])
        if matrix is None:
            return None, status or "unavailable"
        phrases_per_tactic: Dict[str, List[List[float]]] = {}
        for (tactic, _phrase), row in zip(rows, matrix):
            phrases_per_tactic.setdefault(tactic, []).append([float(value) for value in row])
        tactics: List[str] = []
        anchors: List[List[float]] = []
        for tactic in criteria.TACTICS:
            members = phrases_per_tactic.get(tactic)
            if not members:
                continue
            dim = len(members[0])
            mean = [sum(row[axis] for row in members) / len(members) for axis in range(dim)]
            norm = math.sqrt(sum(value * value for value in mean)) or 1.0
            tactics.append(tactic)
            anchors.append([value / norm for value in mean])
        if not anchors:
            return None, "no prototype embeddings were produced"
        self._anchors = (tactics, anchors)
        return self._anchors, None

    async def classify_many(self, state_texts: List[str]) -> List[LabelVerdict]:
        """One embedder call for all texts, one finalize per row. The calibration
        harness applies floors to these vectors instead of re-embedding per grid point."""
        if not state_texts:
            return []
        embedder = self._embedder or _default_embedder()
        matrix, status = await embedder(list(state_texts))
        if matrix is None:
            return [self._unavailable(status or "the embedding model is unavailable")
                    for _ in state_texts]
        anchors, anchor_status = await self._anchor_matrix()
        if anchors is None:
            return [self._unavailable(anchor_status or "prototype anchors unavailable")
                    for _ in state_texts]
        tactics, anchor_rows = anchors
        verdicts: List[LabelVerdict] = []
        for row in matrix:
            vector = [float(value) for value in row]
            similarities = [sum(a * b for a, b in zip(vector, anchor)) for anchor in anchor_rows]
            probabilities = _softmax(similarities, self.temperature)
            verdicts.append(self._finalize(dict(zip(tactics, probabilities))))
        return verdicts

    async def classify(self, state_text: str) -> LabelVerdict:
        return (await self.classify_many([state_text]))[0]

    async def prewarm(self) -> None:
        """Embed the taxonomy prototypes ahead of the first call. The budget is 300 ms
        warm; the cold path is the ONNX session build plus 32 embeddings, which is an
        order of magnitude more than a classify."""
        await self._anchor_matrix()


def _tree_sha256(root: str) -> str:
    """Pin over a vendored model directory. Mirrors what setup.sh generates:
    one ``<file-sha256>  <relative-path>`` line per regular file, ordered by
    relative path, hashed as text. Relative paths mean a moved directory keeps
    its pin; symlinks are skipped because setup.sh's ``find -type f`` skips them.
    """
    entries: List[Tuple[str, str]] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            entries.append((relative, _sha256_file(full)))
    entries.sort(key=lambda item: item[0])
    body = "".join(f"{digest}  {relative}\n" for relative, digest in entries)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _score_payload(payload: Any) -> Optional[Dict[str, float]]:
    """Accept a model-reported score map only when it behaves like a probability
    distribution. Raw logits would pass any floor by construction, which turns a
    threshold into a rubber stamp."""
    if not isinstance(payload, dict) or not payload:
        return None
    values: Dict[str, float] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, (int, float)):
            return None
        values[key] = float(value)
    total = sum(values.values())
    if any(value < 0.0 or value > 1.0 for value in values.values()):
        return None
    if abs(total - 1.0) > 0.05:
        return None
    return values


def _resolve_vendored_root(model_path: str, model_sha256: str,
                           allow_download: bool) -> Optional[str]:
    """Why a pinned model tree may not be loaded, or None when it may. The pin is
    checked before any runtime import and before ``from_pretrained`` unpickles the
    classification head; a remote reference is refused unless downloads were
    explicitly enabled."""
    if not model_sha256:
        return ("no weight pin: set BLUETEAM_LAYA_MODEL_SHA256 "
                "(setup.sh generates it from the vendored tree)")
    if os.path.isdir(model_path):
        actual = _tree_sha256(model_path)
        if actual != model_sha256:
            return (f"weight pin mismatch: {model_path} hashes to {actual}, "
                    f"expected {model_sha256}; refusing to load")
        return None
    if not allow_download:
        return (f"{model_path!r} is not a local directory and "
                "BLUETEAM_LAYA_ALLOW_DOWNLOAD is false")
    return None


class LayaLabeler(_BaseLabeler):
    """Laya-Multilingual classifier. Loads and verifies the weight pin before
    importing the runtime, and never swaps models per request: one agent resident
    is the whole point of the CPU budget, so ``Router`` and ``preload`` are unused.
    ``temperature`` rescales the models own option distribution when it is not 1.0
    (the checkpoint ships uncalibrated), and ``max_len`` is passed through because
    the shipped default of 1024 tokens truncates a 4000-character state text.
    """
    name = "laya"
    def __init__(self, floor: float, model_path: str, model_sha256: str,
                 allow_download: bool = False, temperature: float = 1.0,
                 max_len: int = 1024) -> None:
        super().__init__(floor)
        self.model_path = model_path
        self.model_sha256 = (model_sha256 or "").strip().lower()
        self.allow_download = bool(allow_download)
        self.temperature = float(temperature)
        self.max_len = int(max_len)
        self._agent: Optional[Any] = None
        self._reason = "not loaded"
        self._load_lock = threading.Lock()

    def _load(self) -> bool:
        if self._agent is not None:
            return True
        with self._load_lock:
            if self._agent is not None:
                return True
            refusal = _resolve_vendored_root(self.model_path, self.model_sha256,
                                             self.allow_download)
            if refusal is not None:
                self._reason = refusal
                return False
            try:
                import laya  # noqa: F401 - deliberately inside the call path
                self._agent = laya.load(self.model_path)
                self._reason = "ready"
                logger.info("Laya labeler loaded model=%s", self.model_path)
                return True
            except Exception as exc:
                self._reason = f"model load failed: {exc}"
                logger.warning("Laya labeler unavailable: %s", self._reason)
                return False

    def _predict(self, state_text: str) -> LabelVerdict:
        if not self._load():
            return self._unavailable(self._reason)
        questions = {"tactic": {"type": "choice", "instructions": criteria.QUESTION,
                                "criteria": criteria.criteria_map()}}
        try:
            result = self._agent.predict({"body": state_text}, questions,
                                         max_len=self.max_len)
        except Exception as exc:
            return self._unavailable(f"prediction failed: {exc}")
        answers = result.get("answers") if isinstance(result, dict) else None
        answer = answers.get("tactic") if isinstance(answers, dict) else None
        if not isinstance(answer, dict):
            return self._unavailable("unrecognized laya response shape (no answers.tactic)")
        choice = answer.get("choice")
        if not isinstance(choice, str) or not choice:
            return self._unavailable("unrecognized laya response shape (no answers.tactic.choice)")
        scores = None
        for key in ("scores", "probabilities", "probs", "logits"):
            scores = _score_payload(answer.get(key))
            if scores is not None:
                break
        if scores is None:
            return self._finalize(None, label=choice)
        return self._finalize(_temperature_scale(scores, self.temperature))

    async def classify(self, state_text: str) -> LabelVerdict:
        return await asyncio.to_thread(self._predict, state_text)


class SetFitLabeler(_BaseLabeler):
    """SetFit classifier over the same 16 tactic vocabulary: a sentence transformer
    body plus a logistic-regression head. The tree pin is verified before
    ``from_pretrained`` unpickles ``model_head.pkl``, and the loaded label mapping is
    asserted against ``criteria.TACTICS``; probability columns are mapped by name
    through ``id2label``, never by position, because the column order is whatever
    the training run saved.
    """
    name = "setfit"

    def __init__(self, floor: float, model_path: str, model_sha256: str,
                 allow_download: bool = False, temperature: float = 1.0) -> None:
        super().__init__(floor)
        self.model_path = model_path
        self.model_sha256 = (model_sha256 or "").strip().lower()
        self.allow_download = bool(allow_download)
        self.temperature = float(temperature)
        self._model: Optional[Any] = None
        self._labels: List[str] = []
        self._reason = "not loaded"
        self._load_lock = threading.Lock()

    def _load(self) -> bool:
        if self._model is not None:
            return True
        with self._load_lock:
            if self._model is not None:
                return True
            refusal = _resolve_vendored_root(self.model_path, self.model_sha256,
                                             self.allow_download)
            if refusal is not None:
                self._reason = refusal
                return False
            try:
                from setfit import SetFitModel
                model = SetFitModel.from_pretrained(self.model_path)
            except Exception as exc:
                self._reason = f"model load failed: {exc}"
                logger.warning("SetFit labeler unavailable: %s", self._reason)
                return False
            id2label = getattr(model, "id2label", None) or {}
            labels = [str(id2label[index]) for index in sorted(id2label)]
            if set(labels) != set(criteria.TACTICS):
                self._reason = ("model exposes no label mapping for the criteria "
                                f"vocabulary (got {len(labels)} labels, expected "
                                f"{len(criteria.TACTICS)} tactics)")
                return False
            self._labels = labels
            self._model = model
            self._reason = "ready"
            logger.info("SetFit labeler loaded model=%s", self.model_path)
            return True

    def _predict_many(self, texts: List[str]) -> Optional[List[LabelVerdict]]:
        """Worker-thread path: load, one batched ``predict_proba``, one finalize per
        row. A matrix that is not ``(n_rows, n_labels)`` breaks the output contract,
        so the whole call is unavailable rather than a guessed column mapping."""
        if not self._load():
            return None
        try:
            matrix = self._model.predict_proba(list(texts))
        except Exception as exc:
            self._reason = f"prediction failed: {exc}"
            return None
        rows = getattr(matrix, "tolist", None)
        if callable(rows):
            matrix = rows()
        if not isinstance(matrix, list) or len(matrix) != len(texts):
            self._reason = "unrecognized setfit probability shape"
            return None
        verdicts: List[LabelVerdict] = []
        for row in matrix:
            if not isinstance(row, list) or len(row) != len(self._labels):
                self._reason = "unrecognized setfit probability shape"
                return None
            scores = _score_payload(dict(zip(self._labels, row)))
            if scores is None:
                self._reason = ("setfit did not return a probability distribution; "
                                "refusing to floor raw scores")
                return None
            verdicts.append(self._finalize(_temperature_scale(scores, self.temperature)))
        return verdicts

    async def classify_many(self, state_texts: List[str]) -> List[LabelVerdict]:
        if not state_texts:
            return []
        verdicts = await asyncio.to_thread(self._predict_many, list(state_texts))
        if verdicts is None:
            return [self._unavailable(self._reason) for _ in state_texts]
        return verdicts

    async def classify(self, state_text: str) -> LabelVerdict:
        return (await self.classify_many([state_text]))[0]

    async def prewarm(self) -> None:
        """Load the pinned model ahead of the first call; the request path then pays
        inference only."""
        await asyncio.to_thread(self._load)
        if self._model is None:
            logger.warning("SetFit labeler prewarm failed: %s", self._reason)
