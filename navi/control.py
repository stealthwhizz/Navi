"""Cooperative scan deadlines and cancellation shared by native stages."""

import threading
import time


class ScanStopped(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class ScanControl:
    def __init__(self, seconds=300, event=None, clock=time.monotonic):
        self.event = event or threading.Event()
        self.clock = clock
        self.deadline = clock() + seconds

    def cancel(self):
        self.event.set()

    def check(self):
        if self.event.is_set(): raise ScanStopped("cancelled", "Scan cancelled; completed evidence is retained.")
        if self.clock() >= self.deadline: raise ScanStopped("deadline", "Scan deadline reached; remaining checks were not run.")

    def remaining(self):
        self.check()
        return max(0.001, self.deadline - self.clock())

    def wait(self, seconds):
        self.event.wait(min(seconds, self.remaining()))
        self.check()
