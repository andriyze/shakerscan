"""Read-only AI red-team catalog endpoints.

Extracted verbatim from the api.py monolith (Phase 1 of the decomposition):
these three routes only read the AI red-team artifact catalog and touch no
database, Redis, or application global, so they move behind an APIRouter with a
single import of ``ai_redteam_artifacts`` and no dependency on ``api.api``.
Paths, methods, function names, and behavior are unchanged.
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Response

try:
    from ai_redteam_artifacts import (
        build_ai_learning_guide,
        build_ai_test_case_catalog,
        build_ai_test_case_export,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_redteam_artifacts import (
        build_ai_learning_guide,
        build_ai_test_case_catalog,
        build_ai_test_case_export,
    )


router = APIRouter()


@router.get("/ai/learning-guide")
async def get_ai_learning_guide():
    """Return a ShakerScan-oriented AI red-team learning and capstone map."""
    return build_ai_learning_guide()


@router.get("/ai/test-cases")
async def list_ai_test_cases(pack: Optional[str] = Query(None)):
    """Return AI Gate probe/test-case metadata for eval planning and review."""
    try:
        return build_ai_test_case_catalog(pack=pack)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/ai/test-cases/export")
async def export_ai_test_cases(
    format: str = Query("json", pattern="^(json|promptfoo|pyrit|garak)$"),
    pack: Optional[str] = Query(None),
):
    """Export AI Gate probes into common red-team/eval seed formats."""
    try:
        payload, media_type, extension = build_ai_test_case_export(format, pack=pack)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    filename = f"shakerscan-ai-test-cases.{extension}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if isinstance(payload, (dict, list)):
        return Response(
            content=json.dumps(payload, indent=2),
            media_type=media_type,
            headers=headers,
        )
    return Response(content=payload, media_type=media_type, headers=headers)


__all__ = ["router"]
