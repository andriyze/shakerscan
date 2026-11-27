"""Real pinned Playwright workflow creates and removes a synthetic object."""
import asyncio
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading
from api.capabilities.browser import BrowserWorkflowAdapter
from api.runtime.models import TargetBinding


def test_real_browser_form_and_cleanup_are_metered_and_bounded():
    writes=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            body=b'''<html><body><input id="label"><button id="create" onclick="fetch('/objects',{method:'POST',body:document.querySelector('#label').value}).then(()=>document.querySelector('#status').textContent='created')">Create</button><button id="delete" onclick="fetch('/objects/fixture',{method:'DELETE'}).then(()=>document.querySelector('#status').textContent='deleted')">Cleanup</button><p id="status"></p></body></html>'''
            self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def mutate(self):
            writes.append((self.command,self.path))
            self.rfile.read(int(self.headers.get('Content-Length',0)))
            self.send_response(204);self.end_headers()
        do_POST=mutate
        do_DELETE=mutate
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin=f'http://127.0.0.1:{server.server_port}'
    target=TargetBinding('fixture','web','127.0.0.1',(origin,),('127.0.0.1',),'scope')
    async def run(ceiling):
        prepared=BrowserWorkflowAdapter.prepare(target=target,base_url=origin,args={
            'steps':[{'action':'fill','selector':'#label','value':'synthetic-object'},
                     {'action':'click','selector':'#create'},{'action':'click','selector':'#delete'}],
            'max_state_changing_requests':ceiling,'settle_ms':200,'max_requests':5})
        async def heartbeat(): pass
        return await BrowserWorkflowAdapter(prepared).execute(heartbeat=heartbeat,cancelled=lambda:False)
    try:
        result=asyncio.run(run(2))
        assert writes==[('POST','/objects'),('DELETE','/objects/fixture')],result
        assert result.actual_budget['state_changing_requests']==2
        writes.clear()
        capped=asyncio.run(run(1))
        assert writes==[('POST','/objects')]
        assert capped.actual_budget['state_changing_requests']==1 and capped.status=='partial'
    finally:
        server.shutdown();server.server_close();thread.join(2)
