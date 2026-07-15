#!/usr/bin/env python3
import sys
import threading
import requests
import time
import sseclient
import os

PORT = os.getenv("MCP_PORT", 8000)
BASE_URL = f"http://localhost:{PORT}"

messages_url = None

def read_sse():
    global messages_url
    try:
        response = requests.get(f"{BASE_URL}/sse", stream=True, timeout=None)
        client = sseclient.SSEClient(response)
        for event in client.events():
            if event.event == "endpoint":
                # The MCP server sends the messages URL path in the data field
                messages_url = BASE_URL + event.data
            elif event.data:
                # Forward server responses to stdio
                sys.stdout.write(event.data + "\n")
                sys.stdout.flush()
    except Exception as e:
        sys.stderr.write(f"SSE Error: {e}\n")
        sys.stderr.flush()
        os._exit(1)

# Start background thread to listen to SSE
t = threading.Thread(target=read_sse, daemon=True)
t.start()

# Wait for the initialization event to set the messages URL
timeout = 5.0
start_time = time.time()
while messages_url is None:
    if time.time() - start_time > timeout:
        sys.stderr.write("Timeout waiting for SSE endpoint initialization.\n")
        sys.exit(1)
    time.sleep(0.1)

# Read from stdio and forward to the messages endpoint
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        response = requests.post(
            messages_url,
            data=line.encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
    except Exception as e:
        sys.stderr.write(f"POST Error: {e}\n")
        sys.stderr.flush()
        os._exit(1)
