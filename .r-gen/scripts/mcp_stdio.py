"""Concurrent MCP tool calls with serialized JSON-RPC output.

Slow SSH streams must not prevent HTTP checks or command cancellation on the
same planner connection. IDs correlate out-of-order replies; output and progress
messages share a lock so a client never receives interleaved JSON.
"""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

CONTROL_TOOLS = frozenset({'shakerscan_hunt_ssh_cancel', 'shakerscan_hunt_cancel'})


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
        # JSON-RPC 2.0: a notification (no "id" member) is never answered, not even with an
        # error; answering with id null made clients log a reply to nothing (D9).
        if response is not None and 'id' in request:
            emit(response)
    # Cancelling must remain responsive when execution workers and their bounded queue are full.
    # The separate lane is bounded too; both still use the same server validation and output lock.
    with ThreadPoolExecutor(max_workers=8,thread_name_prefix='hunt-mcp') as pool, \
            ThreadPoolExecutor(max_workers=2,thread_name_prefix='hunt-mcp-control') as control_pool:
        pending = set()
        control_pending = set()
        while True:
            line = stdin.readline(limit+1)
            if not line:
                break
            try:
                if len(line)>limit or not line.endswith(b'\n'):
                    # Discard the rest of the oversized line, so its tail is not parsed as a
                    # second request with its own second error (D9: one line, one error).
                    tail = line
                    while tail and not tail.endswith(b'\n'):
                        tail = stdin.readline(limit+1)
                    raise error_type(-32700,'MCP request exceeded the input cap')
                request = json.loads(line.decode())
                if not isinstance(request,dict):
                    raise error_type(-32600,'JSON-RPC request must be an object')
                if 'id' in request and (request['id'] is None or isinstance(request['id'], bool)
                                        or not isinstance(request['id'], (str, int))):
                    # MCP ids are strings or integers; an object, array, float or null id cannot
                    # be echoed back as a correlation key, so the request is refused unread.
                    raise error_type(-32600,'JSON-RPC id must be a string or an integer')
            except (UnicodeDecodeError,json.JSONDecodeError):
                emit(error_response(None,error_type(-32700,'Invalid JSON')))
                continue
            except error_type as exc:
                emit(error_response(None,exc))
                continue
            pending = {task for task in pending if not task.done()}
            control_pending = {task for task in control_pending if not task.done()}
            if request.get('method')=='tools/call':
                params = request.get('params')
                control = isinstance(params, dict) and isinstance(params.get('name'), str) and params['name'] in CONTROL_TOOLS
                tasks, executor, cap = (control_pending, control_pool, 8) if control else (pending, pool, 32)
                if len(tasks)>=cap:
                    emit(error_response(request.get('id'),error_type(-32009,'Too many concurrent MCP calls')))
                else:
                    tasks.add(executor.submit(handle,request))
            else:
                handle(request)
    return 0
