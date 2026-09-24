#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Incident labeling: one label vocabulary, two interchangeable backends.

``onnx_prototype`` reuses the RAG embedder (fastembed ONNX, already resident) and
scores taxonomy prototypes by cosine similarity. ``laya`` runs the real classifier
and pulls CPU torch. Nothing here imports a model at package scope, so a host with
neither still starts and the tool answers with an enable hint.

Modules and why the wrappers stay separate:
    criteria.py  pure data, no imports beyond constants.py
    backends.py  the two Labeler implementations and the shared LabelVerdict
    labeler.py   backend selection, concurrency gate, state-text builder
"""
