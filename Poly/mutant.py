# enhanced_agent_simulator.py
# Extension of agent_simulator with entropy metrics and randomized params
from __future__ import annotations
import importlib, pkgutil, argparse, json, os, random, base64, logging, math
from datetime import datetime
from typing import List, Tuple, Dict, Any
from abc import ABC, abstractmethod

LOGFILE = "simulator.log"
STATE_FILE = "simulator_state.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

class Transform(ABC):
    name: str = "base"

    # Optional attribute plugins may expose to describe param ranges:
    # param_space = {"key_len": [1,4], "mode": ["fast","safe"]}
    param_space: Dict[str,Any] = {}

    @abstractmethod
    def apply(self, data: bytes, params: Dict[str,Any]=None) -> Tuple[bytes, Dict[str,Any]]:
        """Return (transformed_data, metadata_for_reversion)."""
        pass

    @abstractmethod
    def revert(self, data: bytes, meta: Dict[str,Any]) -> bytes:
        """Revert using metadata returned by apply."""
        pass

def load_plugins(package: str = "plugins") -> List[Transform]:
    transforms: List[Transform] = []
    pkg = importlib.import_module(package)
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        m = importlib.import_module(f"{package}.{modname}")
        for attr in dir(m):
            obj = getattr(m, attr)
            try:
                if isinstance(obj, type) and issubclass(obj, Transform) and obj is not Transform:
                    transforms.append(obj())
            except TypeError:
                continue
    return transforms

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent

def sample_params_from_space(space: Dict[str,Any]) -> Dict[str,Any]:
    params = {}
    for k, v in (space or {}).items():
        if isinstance(v, list):
            # numeric range or discrete options
            if len(v) == 2 and all(isinstance(x, (int,float)) for x in v):
                # treat as inclusive range
                low, high = v
                if isinstance(low, int) and isinstance(high, int):
                    params[k] = random.randint(low, high)
                else:
                    params[k] = random.uniform(low, high)
            else:
                params[k] = random.choice(v)
        elif isinstance(v, dict) and "choices" in v:
            params[k] = random.choice(v["choices"])
        else:
            params[k] = v
    return params

class Agent:
    def __init__(self, transforms: List[Transform], randomize: bool=False, seed: int|None=None):
        self.transforms = transforms.copy()
        self.randomize = randomize
        if seed is not None:
            random.seed(seed)

    def run_once(self, payload: bytes, max_plugins: int|None=None) -> Dict[str,Any]:
        order = self.transforms.copy()
        if max_plugins:
            order = random.sample(order, min(max_plugins, len(order)))
        if self.randomize:
            random.shuffle(order)
        state = {
            "ts": datetime.utcnow().isoformat()+"Z",
            "original_len": len(payload),
            "original_entropy": shannon_entropy(payload),
            "stages": []
        }
        data = payload
        meta_stack = []
        # apply
        for t in order:
            # derive params if plugin offers param_space
            params = sample_params_from_space(getattr(t, "param_space", {}) )
            transformed, meta = t.apply(data, params=params)
            stage = {
                "phase":"apply",
                "transform": t.name,
                "params": params,
                "before_len": len(data),
                "after_len": len(transformed),
                "before_entropy": shannon_entropy(data),
                "after_entropy": shannon_entropy(transformed),
                "meta_summary": {k: type(v).__name__ for k,v in (meta or {}).items()}
            }
            state["stages"].append(stage)
            logging.info("apply %s: %d -> %d ent %.3f->%.3f", t.name, len(data), len(transformed),
                         stage["before_entropy"], stage["after_entropy"])
            meta_stack.append((t.name, meta))
            data = transformed
        # revert in reverse order using meta_stack
        for (tname, meta) in reversed(meta_stack):
            t = next(filter(lambda x: x.name==tname, order))
            reverted = t.revert(data, meta)
            stage = {
                "phase":"revert",
                "transform": t.name,
                "before_len": len(data),
                "after_len": len(reverted),
                "before_entropy": shannon_entropy(data),
                "after_entropy": shannon_entropy(reverted)
            }
            state["stages"].append(stage)
            logging.info("revert %s: %d -> %d ent %.3f->%.3f", t.name, len(data), len(reverted),
                         stage["before_entropy"], stage["after_entropy"])
            data = reverted
        state["recovered_len"] = len(data)
        state["recovered_entropy"] = shannon_entropy(data)
        state["recovery_ok"] = (data == payload)
        # persist state (without payload)
        persist = {k: state[k] for k in ("ts","original_len","original_entropy","recovered_len","recovered_entropy","recovery_ok","stages")}
        with open(STATE_FILE, "w") as f:
            json.dump(persist, f, indent=2)
        with open(LOGFILE, "a") as f:
            f.write(json.dumps(persist) + "\n")
        return state

def cli():
    p = argparse.ArgumentParser()
    p.add_argument("payload", help="Path to benign payload file")
    p.add_argument("--plugins", help="Comma list of plugin names to use", default=None)
    p.add_argument("--randomize", action="store_true", help="Randomize transform order")
    p.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    p.add_argument("--max-plugins", type=int, default=None, help="Max number of plugins to apply")
    args = p.parse_args()

    if not os.path.isfile(args.payload):
        raise SystemExit("payload missing")

    transforms = load_plugins("plugins")
    if args.plugins:
        wanted = set([n.strip() for n in args.plugins.split(",")])
        transforms = [t for t in transforms if t.name in wanted]
    if not transforms:
        raise SystemExit("no transforms loaded")

    with open(args.payload, "rb") as f:
        payload = f.read()

    agent = Agent(transforms, randomize=args.randomize, seed=args.seed)
    result = agent.run_once(payload, max_plugins=args.max_plugins)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    cli()
