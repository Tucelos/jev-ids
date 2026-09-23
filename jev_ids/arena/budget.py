"""The hard cap on what one Run of the Arena may spend.

In reading order:

- `BudgetExhausted`: what a Run raises when it would pass a cap.
- `Budget`: the two counters, the two ways to spend them, what is left and what the Round record keeps.

The Arena is a loop that decides for itself how many calls to make: an attacker that keeps missing spends `max_queries_per_flow` on every
Flow, and a curator asked for two proposals a Round asks twice. That is exactly how an experiment dies halfway. On 2026-09-22 the Jev run
lost its k = 16 cells when the TypeSafe credits ran out (docs/protocol.md, "k stops at 8"), and the protocol was cut rather than bought
back. A Budget makes the wall explicit and hits it in the caller's own stack, where a Round can still be closed and written down. There is
no module-level counter: a Budget belongs to the Run that owns it, so two Runs in one process never eat each other's credits.
"""


class BudgetExhausted(RuntimeError):
    """A call would pass one of a Budget's caps; the Run stops here rather than halfway through the next Round."""


class Budget:
    """The Detector calls and the curator calls one Run of the Arena may still make."""

    def __init__(self, max_detector_calls: int, max_curator_calls: int) -> None:
        """Start both counters at zero under their caps.

        Args:
            max_detector_calls: Detector calls the whole Run may make, the attacker's probes and the evaluation together.
            max_curator_calls: curator calls the whole Run may make.
        """
        self.caps = {"detector_calls": max_detector_calls, "curator_calls": max_curator_calls}
        self.spent = {"detector_calls": 0, "curator_calls": 0}

    def spend_detector(self, n: int = 1) -> None:
        """Book `n` Detector calls, or raise `BudgetExhausted` before any of them is made."""
        self._spend("detector_calls", n)

    def spend_curator(self, n: int = 1) -> None:
        """Book `n` curator calls, or raise `BudgetExhausted` before any of them is made."""
        self._spend("curator_calls", n)

    def _spend(self, kind: str, n: int) -> None:
        """Book `n` calls of one kind; the counter only ever moves when the whole batch fits."""
        if self.spent[kind] + n > self.caps[kind]:
            raise BudgetExhausted(f"{kind}: {self.spent[kind]} of {self.caps[kind]} spent, {n} more asked")
        self.spent[kind] += n

    @property
    def remaining(self) -> dict[str, int]:
        """What is left of each cap; a caller sizes its next batch by this rather than by catching the exception."""
        return {kind: cap - self.spent[kind] for kind, cap in self.caps.items()}

    def snapshot(self) -> dict[str, int]:
        """What each cap was and what was spent against it, for the Run record.

        A Run that ended early is read from this: the record shows whether the loop finished its Rounds or ran out of calls.
        """
        return {
            "detector_calls": self.spent["detector_calls"],
            "max_detector_calls": self.caps["detector_calls"],
            "curator_calls": self.spent["curator_calls"],
            "max_curator_calls": self.caps["curator_calls"],
        }
