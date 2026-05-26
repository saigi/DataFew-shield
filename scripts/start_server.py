"""Start the embedding server directly."""
import sys, os, time
sys.stdout.reconfigure(encoding='utf-8')
os.chdir(os.path.dirname(os.path.abspath(__file__)))
print('Loading embedding_server module...', flush=True)
t0 = time.time()

try:
    from embedding_server import Handler, refs, THRESHOLD, REFS_PATH
except Exception as e:
    print(f'IMPORT ERROR: {e}', flush=True)
    sys.exit(1)

print(f'Module loaded in {time.time()-t0:.0f}s', flush=True)
from http.server import HTTPServer

print(f'Refs: {refs["harmful"]["count"]} harmful, {refs["safe"]["count"]} safe')
print(f'Threshold: {THRESHOLD}')
print(f'Refs path: {REFS_PATH}')

server = HTTPServer(('0.0.0.0', 5000), Handler)
print('Server running on :5000')
try:
    server.serve_forever()
except KeyboardInterrupt:
    server.server_close()
