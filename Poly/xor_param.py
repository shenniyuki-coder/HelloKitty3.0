# plugins/xor_param.py
from enhanced_agent_simulator import Transform
import os

class XORParam(Transform):
    name = "xor_param"
    # allow 1..8 byte keys or single-byte by default
    param_space = {"key_len": [1,8]}

    def apply(self, data: bytes, params=None):
        params = params or {}
        klen = int(params.get("key_len", 1))
        key = os.urandom(klen)
        transformed = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
        return transformed, {"key": key.hex(), "key_len": klen}

    def revert(self, data: bytes, meta):
        key = bytes.fromhex(meta["key"])
        klen = meta["key_len"]
        return bytes(data[i] ^ key[i % klen] for i in range(len(data)))
