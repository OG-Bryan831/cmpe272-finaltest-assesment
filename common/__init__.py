"""Shared, security-agnostic helpers reused by both transfer approaches.

This package contains ONLY the parts that are identical regardless of the
security envelope: chunk sizing, streaming SHA-256, and socket framing.
The cryptographic differences live entirely in each approach's own scripts.
"""
