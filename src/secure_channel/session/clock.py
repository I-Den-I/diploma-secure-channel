# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Time provider abstraction used by the anti-replay machinery.

The session-layer freshness checks --- both *timestamp validation* and
*replay-window* enforcement --- rely on a notion of "now". To keep the
code testable and to make the freshness window deterministic, we
abstract the source of time behind a callable returning the current
Unix-epoch instant in **microseconds** (an :class:`int`).

Production code wires :data:`MICROSECOND_WALL_CLOCK` (which delegates to
:func:`time.time_ns`); unit tests inject a deterministic monotonic
generator so attack scenarios can reproduce edge cases at sub-second
precision without sleeping.

The microsecond resolution was selected because:

* it fits comfortably in an unsigned 64-bit field for any plausible
  date, and
* it offers more than enough granularity to disambiguate records sent
  in rapid succession over a high-throughput interactive channel.
"""

from __future__ import annotations

import time
from typing import Callable, Final

MicrosecondClock = Callable[[], int]
"""Type alias for *callable returning microseconds since the Unix epoch*.

Implementations must return non-negative integers and should be
monotonic when used as the local wall clock --- deviations are tolerated
within :data:`secure_channel.session.records.DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS`.
"""


def _read_wall_clock_microseconds() -> int:
    """Default :data:`MicrosecondClock` implementation.

    Uses :func:`time.time_ns` (which itself delegates to the OS's
    high-resolution monotonic-aware Unix-epoch source) and converts
    nanoseconds to microseconds via integer division. The integer-only
    arithmetic avoids the small floating-point drift that would arise
    from :func:`time.time`.
    """
    return time.time_ns() // 1000


MICROSECOND_WALL_CLOCK: Final[MicrosecondClock] = _read_wall_clock_microseconds
"""Default production clock returning ``time.time_ns() // 1000``."""


__all__: Final[list[str]] = [
    "MICROSECOND_WALL_CLOCK",
    "MicrosecondClock",
]
