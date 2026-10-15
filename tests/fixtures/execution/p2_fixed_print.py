"""Fixed harmless P2-A fixture; no CUDA, filesystem writes or networking."""
import json
import resource
import sys

config = json.loads(sys.stdin.buffer.read(4097))
if set(config) != {"request_id", "nonce", "cpu_seconds", "memory_bytes"}:
    raise ValueError("invalid fixed fixture configuration")
if (type(config["cpu_seconds"]) is not int or not 1 <= config["cpu_seconds"] <= 30
        or type(config["memory_bytes"]) is not int
        or not 67108864 <= config["memory_bytes"] <= 1073741824):
    raise ValueError("invalid fixed fixture resource bounds")
for name in ("request_id", "nonce"):
    if (not isinstance(config[name], str) or len(config[name]) != 32
            or any(char not in "0123456789abcdef" for char in config[name])):
        raise ValueError("invalid fixed fixture identity")
resource.setrlimit(resource.RLIMIT_CPU, (config["cpu_seconds"], config["cpu_seconds"]))
resource.setrlimit(resource.RLIMIT_AS, (config["memory_bytes"], config["memory_bytes"]))
if (resource.getrlimit(resource.RLIMIT_CPU) != (config["cpu_seconds"],) * 2
        or resource.getrlimit(resource.RLIMIT_AS) != (config["memory_bytes"],) * 2):
    raise RuntimeError("resource bounds were not applied")
proof = {"fixture_id": "p2-fixed-print-v1", "request_id": config["request_id"],
         "nonce": config["nonce"], "cpu_seconds": config["cpu_seconds"],
         "memory_bytes": config["memory_bytes"], "message": "harmless fixture completed"}
sys.stdout.write(json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n")
sys.stdout.flush()
