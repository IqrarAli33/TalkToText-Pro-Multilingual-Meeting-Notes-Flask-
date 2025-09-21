# timing_utils.py
import time
from contextlib import contextmanager
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

@contextmanager
def step_timer(label: str):
    t0 = time.perf_counter()
    try:
        yield
    finally:
        dt = time.perf_counter() - t0
        logging.info(f"[TIMING] {label}: {dt:.2f}s")

def timed_call(label: str, fn, *args, **kwargs):
    with step_timer(label):
        return fn(*args, **kwargs)
