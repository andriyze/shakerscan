# API image execution boundary

The 2.2.0 API-image split must preserve the behavior the control-plane process actually owns. A
source audit found a wider boundary than the original release plan assumed.

The API process currently executes:

- Playwright/Chromium through the Python library for interactive sessions and AI Gate widget
  probes;
- Docker Engine API calls over `/var/run/docker.sock` for worker inventory and lifecycle;
- the pinned Docker CLI for Model Intake guest-image staging;
- a fixed `curl` argv for ASM soft-404 and reachability probes; and
- opt-in, bounded version commands for Command Arsenal tools and local planner agents.

Worker-only process execution remains in `api/worker.py`; the Gungnir executable belongs to the
Gungnir worker entrypoint; Firecracker host commands belong to the opt-in Model Intake runner
entrypoint. None of those is API-process authority merely because the source is copied into a
shared image layer.

`tests/test_api_image_boundary.py` freezes the modules that may create subprocesses and rejects a
new direct Go-scanner path in the API process. Before the API image can drop the scanner toolchain,
ASM reachability must move to an in-process target-bound HTTP adapter and version probing must
become worker-reported metadata (or be explicitly retired). Model Intake staging and worker
inventory still require the Docker boundary until the planned narrow internal service replaces it.
