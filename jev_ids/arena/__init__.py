"""The Arena: an adversarial loop around a Detector.

An attacker mutates attack Flows until the Detector stops alerting; a curator rewrites the Detector's Context between Rounds; a simulated
analyst supplies the labels the curator learns from; a gate decides whether a new Context is kept. See docs/arena/ for the protocol.
"""
