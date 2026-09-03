"""Failure collection and progress output for the validation run."""

from __future__ import annotations


class Report:
    """Accumulates problems across checks and prints each one as it is found."""

    def __init__(self) -> None:
        self.failures: list[str] = []
        self._steps = 0

    def begin(self, title: str) -> int:
        """Print a numbered section header and return a marker for `clean_since`."""
        self._steps += 1
        print(f"\n[{self._steps}] {title}")
        return len(self.failures)

    def clean_since(self, marker: int) -> bool:
        return len(self.failures) == marker

    def fail(self, message: str) -> None:
        self.failures.append(message)
        print(f"  FAIL  {message}")

    def ok(self, message: str) -> None:
        print(f"  ok    {message}")

    def skip(self, message: str) -> None:
        print(f"  skip  {message}")

    def note(self, message: str) -> None:
        print(f"        {message}")

    def summarize(self) -> int:
        """Print the final verdict and return the process exit code."""
        print(f"\n{'=' * 70}")
        if self.failures:
            print(f"FAILED: {len(self.failures)} problem(s)")
            for message in self.failures:
                print(f"  - {message}")
            return 1
        print("PASSED: 0 problems")
        return 0
