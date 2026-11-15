"""Small unmodified MCP echo upstream for the ticket's manual verification client."""
import base64
import json
import os
import sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

capture = Path(sys.argv[2])
base_tool = {"name": "echo", "description": "Echo the exact received call and credential representations.",
             "inputSchema": {"type": "object", "properties": {}, "additionalProperties": True}}
extra_tool = {"name": "extra", "description": "Second page tool.", "inputSchema": {"type": "object"}}

def respond(raw, credential):
    request = json.loads(raw)
    method = request.get("method")
    if "id" not in request:
        return None
    envelope = {"jsonrpc": "2.0", "id": request["id"]}
    if method == "initialize":
        # Verify that filesystem roots cannot be replaced by client-supplied roots.
        assert request["params"]["capabilities"] == {}
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {"listChanged": True}},
                  "serverInfo": {"name": "bogo-echo", "version": "1"}}
    elif method == "tools/list":
        if request.get("params", {}).get("cursor") == "page2":
            result = {"tools": [extra_tool]}
        else:
            result = {"tools": [base_tool], "nextCursor": "page2"}
    elif method == "tools/call":
        with capture.open("a") as file:
            file.write(raw.strip() + "\n")
        arguments = raw.split('"arguments":', 1)[1][:-2]
        data = {"wire_arguments": arguments, "credential": credential,
                "base64": base64.b64encode(credential.encode()).decode(),
                "url": "remove-me", "data": {"share": {"link": "remove-too", "keep": True}},
                "array": [{"url": "remove-deep", "keep": 1}]}
        result = {"content": [{"type": "text", "text": json.dumps(data)},
                              {"type": "text", "text": "unstructured output"},
                              {"type": "resource_link", "name": "echo", "uri": credential},
                              {"type": "resource", "resource": {"uri": credential, "text": json.dumps(data)}}],
                  "structuredContent": data, "_meta": {"url": "remove-meta", "credential": credential}}
        # stderr must be scrubbed too, including the base64 representation.
        print(credential + " " + data["base64"], file=sys.stderr, flush=True)
    elif method == "ping":
        result = {}
    else:
        envelope["error"] = {"code": -32601, "message": "method not found"}
        return envelope
    envelope["result"] = result
    return envelope

if sys.argv[1] == "stdio":
    Path(str(capture) + ".pid").write_text(str(os.getpid()))
    for raw in sys.stdin:
        response = respond(raw.strip(), os.environ.get("BOGO_ECHO_CREDENTIAL", "absent"))
        if response is not None:
            print(json.dumps(response), flush=True)
else:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(405)
            self.end_headers()
        def do_DELETE(self):
            self.send_response(204)
            self.end_headers()
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["content-length"])).decode()
            response = respond(raw, self.headers.get("x-echo-credential", "absent"))
            payload = json.dumps(response).encode() if response else b""
            self.send_response(200 if response else 202)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(server.server_port, flush=True)
    server.serve_forever()
