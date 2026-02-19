from collections import deque, Counter
import threading
import time

class InMemoryStore:
    def __init__(self, max_events=5000):
        self.lock = threading.Lock()
        self.events = deque(maxlen=max_events)  # only suspicious/attack/rule
        self.counts = Counter()
        self.last_ts = 0.0

    def add(self, ev: dict):
        with self.lock:
            ts = float(ev.get("ts", time.time()))
            ev["ts"] = ts
            self.last_ts = ts

            verdict = ev.get("verdict", "unknown")
            self.counts[verdict] += 1

            if verdict in ("suspicious", "attack") or ev.get("stage") == "rule":
                self.events.appendleft(ev)

    def get_events(self, limit=200):
        with self.lock:
            return list(self.events)[:limit]

    def get_stats(self):
        with self.lock:
            return {
                "counts": dict(self.counts),
                "last_ts": self.last_ts,
                "queue_len": len(self.events),
            }

STORE = InMemoryStore(max_events=5000)
