"""Authorization modes reuse shared proof contracts and frozen HTTP execution."""
import hashlib
import asyncio
import math
import time
from urllib.parse import urlsplit
from .authz import _normalized_routes, AuthzVerificationContractError
from .authz_surface import PrincipalProbe, RouteComparison, boundary_established, bfla_finding
from .http import execute_bound_http_request
try:
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:
    from scanner.scanner_tools.url_redaction import redact_url


def authz_call_budget(values):
    if values.get('mode','object') == 'function':
        if not 1<=len(values['routes'])<=10:
            raise ValueError('Function authorization checks accept 1 to 10 routes')
        return {'http_requests':6*len(values['routes']),'tool_wall_seconds':60}
    return {'http_requests':4,'tool_wall_seconds':60}


async def verify_function_authorization(base_url,routes,*,target,primary_headers,
                                        secondary_headers,transaction_recorder=None):
    normalized=_normalized_routes(base_url,routes,target=target)
    if len(normalized)!=len(routes) or not 1<=len(normalized)<=10:
        raise AuthzVerificationContractError('Function comparison requires 1 to 10 bound GET routes')
    if not primary_headers or not secondary_headers or dict(primary_headers)==dict(secondary_headers):
        raise AuthzVerificationContractError('Function comparison requires two distinct authenticated principals')
    started=time.monotonic()
    attempted=0
    comparisons=[]
    observations=[]
    incomplete=False
    async def send(url,slot,headers):
        nonlocal attempted
        parsed=urlsplit(url)
        origin=parsed.scheme+'://'+parsed.netloc
        path=parsed.path+('?' + parsed.query if parsed.query else '')
        captured=[];archive={}
        def record(value):
            archive.update(value)
            if transaction_recorder: transaction_recorder(value)
        remaining=55-(time.monotonic()-started)
        if remaining<=0:
            return PrincipalProbe(0,'',0,False,True)
        try:
            result=await asyncio.wait_for(execute_bound_http_request(origin,{'method':'GET','path':path,'follow_redirects':False},
                target=target,allow_write=False,trusted_headers=headers,principal_slot=slot,
                selected_headers=['content-type'],timeout_seconds=min(8,remaining),
                private_response_sink=captured.append,transaction_recorder=record),timeout=remaining)
        except TimeoutError:
            attempted+=1  # An in-flight request is uncertain, never refunded.
            return PrincipalProbe(0,'',0,False,True)
        if not result.get('ok') and str(result.get('error') or '').startswith('scope:'):
            raise AuthzVerificationContractError('Function comparison left its frozen target')
        attempted+=int(isinstance(result.get('request'),dict))
        if not captured:
            return PrincipalProbe(0,'',0,False,True)
        response=captured[0];body=response.body()
        complete=archive.get('response_digest_scope')=='complete' and archive.get('response_body_truncated') is False
        content_type={key.lower():value for key,value in response.headers().items()}.get('content-type','').split(';')[0]
        return PrincipalProbe(response.status_code,hashlib.sha256(body).hexdigest(),len(body),
            content_type=='application/json' or content_type.endswith('+json'),
            not result.get('ok') or not complete)
    for url in normalized:
        probes={slot:[] for slot in ('anonymous','primary','secondary')}
        for _ in range(2):
            for slot,headers in (('anonymous',{}),('primary',primary_headers),('secondary',secondary_headers)):
                probes[slot].append(await send(url,slot,headers))
        identifier=hashlib.sha256(url.encode()).hexdigest()
        comparisons.append(RouteComparison(identifier,redact_url(url),tuple(probes['anonymous']),tuple(probes['primary'])))
        observations.append({'kind':'authorization_matrix_observation','mode':'function',
            'url':redact_url(url),'principal_contexts_distinct':True,'proof_state':'observation_only',
            'principals':{slot:[{'status':p.status,'body_sha256':p.body_sha256,'body_len':p.body_len,
                'complete':not p.error} for p in values] for slot,values in probes.items()},
            'entitlement_inferred':False,'secret_values_visible':False})
        incomplete = incomplete or any(p.error for values in probes.values() for p in values)
        if time.monotonic()-started>=55:
            break
    if boundary_established(comparisons):
        for row in comparisons:
            if (value:=bfla_finding(row)) is not None:
                # Equivalence proves access, not the application's intended role
                # policy. Keep this a lead, as the shared Scan finalizer does.
                observations.append({**value,'kind':'authorization_matrix_observation',
                    'mode':'function','proof_state':'observation_only','finding_verdict':'suspected',
                    'entitlement_inferred':False})
    return {'ok':True,'status':'partial' if incomplete or len(comparisons)!=len(normalized) else 'success','observations':observations,
        'coverage_gaps':['Function comparisons incomplete'] if incomplete or len(comparisons)!=len(normalized) else [],
        'budget_consumed':{'http_requests':attempted,'tool_wall_seconds':math.ceil(time.monotonic()-started)}}
