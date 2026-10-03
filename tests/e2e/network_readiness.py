"""Bounded startup polling for the network pool; starting never counts as ready."""
import time


def wait_network_readiness(fetch, *, timeout=120, interval=2, clock=None, pause=None):
    clock = clock or time.monotonic
    pause = pause or time.sleep
    deadline = clock() + timeout
    while True:
        result = fetch()
        if result.get('status') != 'starting':
            return result
        remaining = deadline - clock()
        if remaining <= 0:
            return result
        pause(min(interval, remaining))
