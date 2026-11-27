# Contributing to ShakerScan

Thank you for your interest in ShakerScan.

ShakerScan is open source, but it is not open to outside code contributions. Keeping a single
author for the code keeps its safety model, evidence rules and architecture consistent, which
matters for a tool that sends traffic to real systems.

## How you can help

These are the contributions that help most, and they are very welcome:

- **Bug reports.** Open an [issue](https://github.com/andriyze/shakerscan/issues/new/choose) with
  the version, deployment mode, steps to reproduce, and what you expected.
- **False positives and false negatives.** A minimal reproduction (for example a small
  Docker-hosted test app or a redacted request/response pair) is the most valuable report a
  scanner can receive.
- **Feature requests and use cases.** Describe the problem you are trying to solve rather than a
  specific implementation.
- **Documentation gaps.** Tell us what was unclear or missing.
- **Security vulnerabilities.** Please report these privately as described in
  [SECURITY.md](SECURITY.md), never in a public issue.

## Pull requests

Pull requests containing code are closed without review. If you have found a fix, please describe
the problem and your approach in an issue instead; the maintainer may implement it independently.

Please do not paste large code patches into issues, and never include credentials, tokens, or data
from systems you are not authorized to share.

## Code of conduct

Participation in this project's issues and discussions is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).
