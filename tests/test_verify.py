from types import SimpleNamespace

import tartarus.verify
from tartarus.verify import _clock_ok


class ClockRemote:
    def __init__(self, epoch: int):
        self.epoch = epoch

    def run(self, _command):
        return SimpleNamespace(stdout=f"{self.epoch}\n")


def test_clock_check_accepts_contained_guest_with_low_skew(monkeypatch) -> None:
    times = iter((1000.0, 1002.0))
    monkeypatch.setattr(tartarus.verify.time, "time", lambda: next(times))

    assert _clock_ok(ClockRemote(1001))


def test_clock_check_rejects_guest_with_high_skew(monkeypatch) -> None:
    times = iter((1000.0, 1002.0))
    monkeypatch.setattr(tartarus.verify.time, "time", lambda: next(times))

    assert not _clock_ok(ClockRemote(1010))
