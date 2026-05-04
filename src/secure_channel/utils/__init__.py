# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Reserved namespace for cross-cutting utility helpers.

The package is intentionally empty in the diploma submission: every
helper that any of the cryptographic, session or network modules needs
lives next to its primary consumer (e.g.
:mod:`secure_channel.session.clock` for the microsecond wall clock,
:mod:`secure_channel.network.framing` for length-prefix framing). Should
genuinely cross-package utilities be required in a future revision they
should land here rather than be duplicated.
"""

from __future__ import annotations
