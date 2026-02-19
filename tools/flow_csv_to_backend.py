

# tools/flow_csv_to_backend.py (ý tưởng chính)
import argparse, time, requests, pandas as pd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--nrows", type=int, default=50000)
    ap.add_argument("--backend", required=True)
    ap.add_argument("--endpoint", default="/api/ingest_bulk")
    ap.add_argument("--batch", type=int, default=200)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    df = pd.read_csv(args.csv, nrows=args.nrows)
    # tách gt nếu có
    gt_label = df["Label"].astype(int).tolist() if "Label" in df.columns else None
    gt_attack = df["Attack"].astype(str).tolist() if "Attack" in df.columns else None
    flow_df = df.drop(columns=[c for c in ["Label","Attack"] if c in df.columns])

    url = args.backend.rstrip("/") + args.endpoint

    items = []
    sent = 0
    for i in range(len(flow_df)):
        flow = flow_df.iloc[i].to_dict()
        it = {"flow": flow}
        if gt_label is not None: it["gt_label"] = int(gt_label[i])
        if gt_attack is not None: it["gt_attack"] = gt_attack[i]
        items.append(it)

        if len(items) >= args.batch:
            r = requests.post(url, json={"items": items, "ts0": time.time()}, timeout=args.timeout)
            r.raise_for_status()
            sent += len(items)
            print(f"[POST] {sent}/{args.nrows} ok")
            items = []

    if items:
        r = requests.post(url, json={"items": items, "ts0": time.time()}, timeout=args.timeout)
        r.raise_for_status()
        sent += len(items)
        print(f"[POST] {sent}/{args.nrows} ok")

if __name__ == "__main__":
    main()
