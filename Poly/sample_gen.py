# sample_generator.py
# Create many randomized training samples by applying randomized sequences of transforms.
# Produces reversible samples + metadata. Safe: reversible transforms only.
import os, argparse, json, random, shutil
from enhanced_agent_simulator import load_plugins, Agent
from datetime import datetime

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def generate_samples(payload_path: str, outdir: str, count: int = 100, max_plugins:int|None=3, seed:int|None=None):
    if seed is not None:
        random.seed(seed)
    transforms = load_plugins("plugins")
    if not transforms:
        raise SystemExit("no plugins found")
    ensure_dir(outdir)
    # read payload once
    with open(payload_path, "rb") as f:
        payload = f.read()
    for i in range(count):
        run_seed = random.randint(0,2**32-1)
        agent = Agent(transforms, randomize=True, seed=run_seed)
        result = agent.run_once(payload, max_plugins=max_plugins)
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        sample_dir = os.path.join(outdir, f"sample_{i:05d}_{stamp}")
        ensure_dir(sample_dir)
        # store metadata
        with open(os.path.join(sample_dir, "meta.json"), "w") as mf:
            json.dump({"seed": run_seed, "result": result}, mf, indent=2)
        # store transformed payload (the final transformed data)
        # to get final transformed data we re-run applying transforms and capture final data
        # using the same seed to reproduce
        agent = Agent(transforms, randomize=True, seed=run_seed)
        # extract final transformed bytes by replicating internal apply sequence
        # lightweight re-implementation: use private run to get final data by applying transforms only
        data = payload
        order = agent.transforms.copy()
        if agent.randomize:
            random.shuffle(order)
        if max_plugins:
            order = random.sample(order, min(max_plugins, len(order)))
        for t in order:
            params = {}
            space = getattr(t, "param_space", {})
            # simple param sampling re-use same logic as enhanced_agent_simulator.sample_params_from_space
            for k,v in (space or {}).items():
                if isinstance(v,list):
                    if len(v)==2 and all(isinstance(x,(int,float)) for x in v):
                        low,high = v
                        params[k] = random.randint(low,high) if isinstance(low,int) else random.uniform(low,high)
                    else:
                        params[k] = random.choice(v)
                elif isinstance(v,dict) and "choices" in v:
                    params[k] = random.choice(v["choices"])
                else:
                    params[k] = v
            transformed, meta = t.apply(data, params=params)
            data = transformed
        # write final transformed bytes
        with open(os.path.join(sample_dir, "transformed.bin"), "wb") as tf:
            tf.write(data)
    print(f"wrote {count} samples to {outdir}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("payload", help="benign payload path")
    p.add_argument("outdir", help="output directory")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--max-plugins", type=int, default=3)
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()
    generate_samples(args.payload, args.outdir, count=args.count, max_plugins=args.max_plugins, seed=args.seed)
