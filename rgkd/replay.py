from __future__ import annotations

from . import constants


class ReplayWindow:
    """Sliding bitmap window for (MemberID, state_seq, epoch) counters.

    Call check() before AEAD/signature. Call commit() only after both succeed.
    Unauthenticated packets must not advance max_c or the bitmap.
    """

    def __init__(self, window_size: int = constants.REPLAY_WINDOW_MIN) -> None:
        if window_size < constants.REPLAY_WINDOW_MIN:
            raise ValueError(
                f"replay window must be at least {constants.REPLAY_WINDOW_MIN}",
            )
        self.window_size = window_size
        # max_c < 0 means no counter has been committed yet
        self.max_c = -1
        self._seen: set[int] = set()

    def check(self, counter: int) -> bool:
        """Tentative replay test. Does not mutate window state."""
        if counter < 0 or counter > 0xFFFFFFFF:
            return False
        if self.max_c < 0:
            return True
        if counter <= self.max_c and self.max_c - counter >= self.window_size:
            return False
        if counter in self._seen:
            return False
        return True

    def commit(self, counter: int) -> None:
        """Record counter after successful AEAD and optional member signature."""
        if not self.check(counter):
            raise ValueError("counter failed tentative replay check")
        self._seen.add(counter)
        if counter > self.max_c:
            self.max_c = counter
            cutoff = self.max_c - self.window_size
            if cutoff >= 0:
                self._seen = {c for c in self._seen if c > cutoff}
