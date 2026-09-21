"""Detectors: Jev, the two LLM baselines and the Random Forest.

Each detector is a class with `name`, `model`, `prompt_hash` and `predict(flow, examples) -> dict` returning what it measured for that one
Flow (`p_attack`, `category_pred`, `latency_ms`, ...) or an `error`. The run loop treats the three alike without a shared base class.
"""
