import asyncio
from copy import deepcopy
import io
import json
import threading
from types import SimpleNamespace
from email.message import Message
import pytest
from api.capabilities import authz_modes
from api.capabilities.http import WorkerPrivateHTTPResponse
from api.capabilities.snmp import SnmpInspectAdapter
from api.hunt.continuation import prior_handoff
from scripts.mcp_ssh_stream import ssh_events
from scripts import shakerscan_mcp as mcp
from tests.test_authz_capability import TARGET


@pytest.mark.parametrize('public,truncated',[(False,False),(True,False),(False,True)])
def test_function_matrix_retains_principals_and_never_invents_role_entitlement(monkeypatch,public,truncated):
    calls=[]
    async def send(origin,args,**kwargs):
        calls.append((origin,args,kwargs['principal_slot']))
        assert kwargs['allow_write'] is False and args['follow_redirects'] is False
        denied=args['path']=='/boundary' and kwargs['principal_slot']=='anonymous' and not public
        status=403 if denied else 200
        body=json.dumps({'fixture':'stable JSON data with enough content for comparison'}).encode()
        kwargs['private_response_sink'](WorkerPrivateHTTPResponse(status,origin+args['path'],body,
            {'Content-Type':'application/json'},{}))
        kwargs['transaction_recorder']({'response_digest_scope':'complete','response_body_truncated':truncated})
        return {'ok':True,'request':args,'response':{'status':status}}
    monkeypatch.setattr(authz_modes,'execute_bound_http_request',send)
    result=asyncio.run(authz_modes.verify_function_authorization('https://app.example.test',
        ['/boundary','/data'],target=TARGET,primary_headers={'Authorization':'Bearer primary-secret'},
        secondary_headers={'Authorization':'Bearer secondary-secret'}))
    assert len(calls)==12 and result['budget_consumed']['http_requests']==12
    assert {slot for _,_,slot in calls}=={'primary','secondary','anonymous'}
    assert result['status']==('partial' if truncated else 'success')
    leads=[row for row in result['observations'] if row.get('technique')]
    assert bool(leads)==(not public and not truncated)
    assert all(row['proof_state']=='observation_only' and row['entitlement_inferred'] is False for row in result['observations'])
    assert 'primary-secret' not in json.dumps(result)


def test_function_matrix_refuses_another_asset_before_traffic(monkeypatch):
    async def unexpected(*args,**kwargs): raise AssertionError('Network reached')
    monkeypatch.setattr(authz_modes,'execute_bound_http_request',unexpected)
    with pytest.raises(authz_modes.AuthzVerificationContractError):
        asyncio.run(authz_modes.verify_function_authorization('https://app.example.test',['https://other.test/'],
            target=TARGET,primary_headers={'Cookie':'a'},secondary_headers={'Cookie':'b'}))
    assert authz_modes.authz_call_budget({'mode':'function','routes':['/a','/b']})['http_requests']==12


def test_snmp_is_one_frozen_udp_service_without_community_or_mutation():
    from api.runtime.models import TargetBinding,ScanPolicy
    target=TargetBinding('asset','network','router.test',(),('192.0.2.10',),'scope')
    adapter=SnmpInspectAdapter()
    prepared=adapter.prepare(target=target,args={'port':1161},policy=ScanPolicy(
        active_testing=True,network_discovery=True,approval_receipt_id='receipt'))
    command=prepared.commands[0]
    assert '-sU' in command.argv and command.argv[-1]=='192.0.2.10'
    assert '+snmp-info' in command.argv and '1161' in command.argv
    assert prepared.estimated_budget['udp_ports_attempted']==1
    assert not any('community' in item or 'snmp-set' in item for item in command.argv)
    parsed=adapter.parse('<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="udp" portid="1161"><state state="open"/><script id="snmp-info" output="enterprise: fixture"/></port></ports></host></nmaprun>',expected_ports=[1161],expected_scripts=['snmp-info'])
    assert parsed.observations and parsed.observations[0]['proof_state']=='observation_only'


def test_prior_handoff_is_bounded_advisory_and_exact_target():
    row={'id':'prior-hunt','status':'budget_exhausted','final_debrief':json.dumps({
        'summary':'x'*5000,'next_actions':['inspect logs']*20})}
    class Conn:
        async def fetchrow(self,sql,identifier):
            assert identifier=='exact-target' and 'target_id=$1' in sql
            return deepcopy(row)
    result=asyncio.run(prior_handoff(Conn(),'exact-target'))
    assert result['source_hunt_id']=='prior-hunt' and result['advisory_only'] and not result['authority_granted']
    assert len(result['summary'])==2000 and len(result['next_actions'])==10


def test_mcp_ssh_stream_emits_progress_and_never_replays_early_disconnect():
    class Response(io.BytesIO):
        headers=Message()
        headers['Content-Type']='text/event-stream'
    calls=[]
    class Opener:
        def open(self,request,**kwargs):
            calls.append(request)
            return Response(b'event: accepted\ndata: {"action_id":"one"}\n\nevent: output\ndata: {"stdout":"first"}\n\n')
    events=[]
    with pytest.raises(ValueError,match='inspect action one'):
        ssh_events(SimpleNamespace(base_url='http://localhost',api_token=None,opener=Opener()),'/stream',{},
            lambda event,value:events.append((event,value)))
    assert len(calls)==1 and events[1]==('output',{'stdout':'first'})


def test_mcp_can_cancel_a_stream_and_run_external_check_on_same_connection():
    started=threading.Event();release=threading.Event()
    class Client:
        def call_tool(self,name,args):
            if name=='ssh':
                started.set()
                assert release.wait(3),'MCP serialized cancellation behind SSH'
                return {'closed':True}
            assert started.wait(3)
            if name=='cancel': release.set()
            return {'tool':name}
    requests=[{'jsonrpc':'2.0','id':index,'method':'tools/call','params':{'name':name}}
        for index,name in enumerate(('ssh','http','cancel'))]
    output=io.BytesIO()
    assert mcp.serve(mcp.MCPServer(Client()),io.BytesIO(b''.join(json.dumps(row).encode()+b'\n' for row in requests)),output)==0
    replies={row['id']:row for row in map(json.loads,output.getvalue().splitlines())}
    assert set(replies)=={0,1,2} and all('result' in row for row in replies.values())


def test_ssh_preserves_buffered_output_when_exec_acknowledgement_is_lost():
    from api.capabilities.ssh_channel import OutputCapture,run_command
    class Channel:
        data=b'partial remote output'
        def settimeout(self,value): pass
        def exec_command(self,value): raise EOFError('closed during acknowledgement')
        def recv_ready(self): return bool(self.data)
        def recv(self,size): data=self.data;self.data=b'';return data
        def recv_stderr_ready(self): return False
        def recv_stderr(self,size): return b''
        def close(self): pass
    channel=Channel();capture=OutputCapture(1024)
    session=SimpleNamespace(transport=SimpleNamespace(open_session=lambda **kwargs:channel))
    result=run_command(session,{'timeout_seconds':1},command='fixture-command',cwd=None,
        stopped=lambda:False,capture=capture,on_progress=lambda value:None)
    assert result['command_dispatched'] and result['execution_uncertain']
    assert capture.public(final=True)['stdout']=='partial remote output'
