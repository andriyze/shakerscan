"""Server-derived human identity shared by operator decision routes."""
from fastapi import HTTPException, Request


def operator_identity(request: Request) -> str:
    """The server-derived operator identity. A request through the planner ingress is never one."""
    if request.scope.get('shakerscan.planner_identity') or request.scope.get('shakerscan.planner_hunt_id'):
        raise HTTPException(403, {'error': 'operator_only', 'reason_code': 'operator_only',
                                  'message': 'This is an operator route; a Hunt planner cannot use it.'})
    actor = str(request.scope.get('shakerscan.operator_identity') or 'operator:interpretations-api')
    return (actor if actor.startswith('operator:') else f'operator:{actor}')[:200]


