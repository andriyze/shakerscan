"""Concurrent MCP tool calls with serialized JSON-RPC output.

Slow SSH streams must not prevent HTTP checks or command cancellation on the
same planner connection. IDs correlate out-of-order replies; output and progress
messages share a lock so a client never receives interleaved JSON.
"""
import json
import threading
from concurrent.futures import ThreadPoolExecutor


def serve(server, stdin, stdout, *, limit, error_type, error_response):
    lock = threading.Lock()
    def emit(message):
        encoded = json.dumps(message,separators=(',',':'),default=str).encode()+b'\n'
        with lock:
            stdout.write(encoded)
            stdout.flush()
    server.notify = emit
    def handle(request):
        try:
            response = server.handle(request)
        except error_type as exc:
            response = error_response(request.get('id'),exc)
        except Exception:
            # Never expose command text, tokens or upstream response bodies.
            response = error_response(request.get('id'),error_type(-32603,'MCP request failed'))
        if response is not None:
            emit(response)
    with ThreadPoolExecutor(max_workers=8,thread_name_prefix='hunt-mcp') as pool:
        pending = set()
        while True:
            line = stdin.readline(limit+1)
            if not line:
                break
            try:
                if len(line)>limit or not line.endswith(b'\n'):
                    raise error_type(-32700,'MCP request exceeded the input cap')
                request = json.loads(line.decode())
                if not isinstance(request,dict):
                    raise error_type(-32600,'JSON-RPC request must be an object')
            except (UnicodeDecodeError,json.JSONDecodeError):
                emit(error_response(None,error_type(-32700,'Invalid JSON')))
                continue
            except error_type as exc:
                emit(error_response(None,exc))
                continue
            pending = {task for task in pending if not task.done()}
            if request.get('method')=='tools/call':
                if len(pending)>=32:
                    emit(error_response(request.get('id'),error_type(-32009,'Too many concurrent MCP calls')))
                else:
                    pending.add(pool.submit(handle,request))
            else:
                handle(request)
    return 0
