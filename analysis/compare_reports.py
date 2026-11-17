#!/usr/bin/env python3
"""Compare on-device AI fingerprint reports downloaded from local_model.html.

Usage:
    python3 analysis/compare_reports.py ~/Downloads/local_model_*.json
    python3 analysis/compare_reports.py reports_dir/ --csv features.csv
    python3 analysis/compare_reports.py a.json b.json --show-constant --no-dedupe

What it reports:
  1. Devices          one line per device (label, browser, hashes, model availability)
  2. Entropy          Shannon entropy of each feature group, anonymity-set sizes, and
                      the extra bits the AI APIs add beyond UA + hardware (H(AI | baseline))
  3. Anonymity sets   which devices share a passive / full fingerprint
  4. Differing features   every fingerprint feature that is not identical across devices
  5. Timing           inference / availability() timing per device
  6. Pairwise         number of differing AI features between each pair of devices
  7. Stability        for device labels seen in several files: what changed between runs

Reports with the same device label are treated as repeat runs of one device; only the
latest one counts toward entropy (use --no-dedupe to count every file).

Standard library only; works on Python 3.8+.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

POC_ID = "on-device-ai-fingerprint"
MISSING = "∅"

PASSIVE_PREFIXES = ("presence.", "surface.", "params", "avail.")
ACTIVE_PREFIXES = ("lm.", "det.", "sum.", "tr.")


# --------------------------------------------------------------------------- helpers
def jstr(v) -> str:
    """Canonical string for a JSON value (stable across key order)."""
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    if v is None:
        return MISSING
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def trunc(s: str, width: int) -> str:
    s = s.replace("\n", " ")
    return s if len(s) <= width else s[: width - 1] + "…"


def median_or_none(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    return round(statistics.median(xs), 2) if xs else None


def entropy(values) -> float:
    counts = Counter(values)
    n = sum(counts.values())
    return -sum(c / n * math.log2(c / n) for c in counts.values()) if n else 0.0


def print_table(headers, rows, max_width=48):
    rows = [[trunc(MISSING if c is None else str(c), max_width) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)))


def section(title: str):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


# ------------------------------------------------------------------ feature extraction
def extract_features(d: dict) -> dict:
    """Categorical fingerprint features (mirrors what the page hashes, flattened)."""
    f = {}

    # ---- passive
    for api, v in (d.get("presence") or {}).items():
        f[f"presence.{api}"] = jstr(v) if isinstance(v, list) else jstr(bool(v))
    for api, s in (d.get("surface") or {}).items():
        f[f"surface.{api}.statics"] = ",".join(s.get("statics") or [])
        f[f"surface.{api}.prototype"] = ",".join(s.get("prototype") or [])
    f["params"] = jstr(d.get("params"))
    for a in d.get("availability") or []:
        f[f"avail.{a.get('api')}|{a.get('variant')}"] = a.get("result") or f"ERR:{a.get('errorName', '?')}"

    # ---- active
    act = d.get("active") or {}

    lm = act.get("languageModel")
    if isinstance(lm, dict):
        f["lm.status"] = "error:" + lm["error"].split(":")[0] if lm.get("error") else "ran"
        f["lm.samplingParams"] = jstr(lm.get("samplingParams"))
        f["lm.measureMethod"] = jstr(lm.get("measureMethod"))
        for k, v in (lm.get("session") or {}).items():
            f[f"lm.session.{k}"] = jstr(v)
        tc = lm.get("tokenCounts")
        if isinstance(tc, dict):
            for k, v in tc.items():
                f[f"lm.tokens.{k}"] = jstr(v)
        else:
            f["lm.tokens"] = jstr(tc)
        runs = [r for r in lm.get("shortRuns") or [] if r.get("ok")]
        f["lm.shortDeterministic"] = jstr(lm.get("shortDeterministic"))
        f["lm.shortOutput"] = runs[0].get("sha256") if lm.get("shortDeterministic") and runs else "nondeterministic"
        f["lm.shortOutputText"] = runs[0].get("text", "").strip() if runs else MISSING
        lr = lm.get("longRun") or {}
        f["lm.longOutput"] = lr.get("sha256") if lr.get("ok") else MISSING
        f["lm.longOutputTokens"] = jstr(lr.get("outputTokens"))
    else:
        f["lm.status"] = jstr(lm)

    det = act.get("languageDetector")
    if isinstance(det, dict):
        f["det.status"] = "error:" + det["error"].split(":")[0] if det.get("error") else "ran"
        for r in det.get("results") or []:
            top = r.get("top")
            f[f"det.{r.get('text')}"] = (
                " ".join(f"{x.get('lang')}:{x.get('confidence')}" for x in top) if isinstance(top, list) else jstr(top)
            )
    else:
        f["det.status"] = jstr(det)

    sm = act.get("summarizer")
    if isinstance(sm, dict):
        f["sum.status"] = "error:" + sm["error"].split(":")[0] if sm.get("error") else "ran"
        f["sum.inputQuota"] = jstr(sm.get("inputQuota"))
        shas = [r.get("sha256") for r in sm.get("runs") or [] if r.get("sha256")]
        f["sum.output"] = shas[0] if shas and len(set(shas)) == 1 else ("nondeterministic" if shas else MISSING)
    else:
        f["sum.status"] = jstr(sm)

    tr = act.get("translator")
    if isinstance(tr, dict):
        f["tr.status"] = "error:" + tr["error"].split(":")[0] if tr.get("error") else "ran"
        f["tr.pair"] = jstr(tr.get("pair"))
        f["tr.output"] = jstr(tr.get("text"))
    else:
        f["tr.status"] = jstr(tr)

    return f


def browser_version(ctx: dict) -> str:
    for b in (ctx.get("uaCH") or {}).get("fullVersionList") or []:
        if b.get("brand") in ("Google Chrome", "Chromium", "Microsoft Edge", "Brave", "Opera"):
            return f"{b['brand']} {b.get('version')}"
    m = re.search(r"(Edg|OPR|Chrome|Firefox|Version)/([\d.]+)", ctx.get("userAgent") or "")
    return m.group(0) if m else MISSING


def extract_baseline(d: dict) -> dict:
    """Pre-existing fingerprint surface: UA + hardware. Used as the conditioning set."""
    ctx = d.get("context") or {}
    ch = ctx.get("uaCH") or {}
    gpu = ctx.get("webgpu")
    return {
        "base.userAgent": jstr(ctx.get("userAgent")),
        "base.browser": browser_version(ctx),
        "base.platform": jstr(ch.get("platform") or ctx.get("platform")),
        "base.platformVersion": jstr(ch.get("platformVersion")),
        "base.architecture": jstr(ch.get("architecture")),
        "base.model": jstr(ch.get("model")),
        "base.hardwareConcurrency": jstr(ctx.get("hardwareConcurrency")),
        "base.deviceMemory": jstr(ctx.get("deviceMemory")),
        "base.webgpu": jstr(gpu),
        "base.languages": jstr(ctx.get("languages")),
        "base.timezone": jstr(ctx.get("timezone")),
    }


def extract_numeric(d: dict) -> dict:
    n = {}
    t = d.get("availabilityTiming") or {}
    n["avail.firstCall.ms"] = (t.get("firstCall") or {}).get("ms")
    for api in ("LanguageModel", "LanguageDetector", "Summarizer"):
        n[f"avail.{api}.warm.median.ms"] = (t.get(api) or {}).get("median")

    act = d.get("active") or {}
    lm = act.get("languageModel")
    if isinstance(lm, dict):
        runs = [r for r in lm.get("shortRuns") or [] if r.get("ok")]
        lr = lm.get("longRun") or {}
        n["lm.create.ms"] = lm.get("createMs")
        n["lm.short.ttft.median.ms"] = median_or_none([r.get("ttftMs") for r in runs])
        n["lm.short.total.median.ms"] = median_or_none([r.get("totalMs") for r in runs])
        n["lm.long.ttft.ms"] = lr.get("ttftMs")
        n["lm.long.total.ms"] = lr.get("totalMs")
        n["lm.long.decode.tok_per_s"] = lr.get("decodeTokensPerSec")
    det = act.get("languageDetector")
    if isinstance(det, dict):
        n["det.create.ms"] = det.get("createMs")
        n["det.detect.median.ms"] = median_or_none([r.get("ms") for r in det.get("results") or []])
    sm = act.get("summarizer")
    if isinstance(sm, dict):
        n["sum.create.ms"] = sm.get("createMs")
        n["sum.summarize.median.ms"] = median_or_none([r.get("ms") for r in sm.get("runs") or []])
    tr = act.get("translator")
    if isinstance(tr, dict):
        n["tr.create.ms"] = tr.get("createMs")
        n["tr.translate.ms"] = tr.get("translateMs")
    n["ctx.storageQuotaGB"] = (d.get("context") or {}).get("storageQuotaGB")
    return n


# ----------------------------------------------------------------------------- loading
class Report:
    def __init__(self, path: Path, data: dict):
        meta = data.get("meta") or {}
        self.path = path
        self.data = data
        self.label = (meta.get("deviceLabel") or "").strip() or path.stem
        self.collected_at = meta.get("collectedAt") or ""
        self.hashes = data.get("hashes") or {}
        self.features = extract_features(data)
        self.baseline = extract_baseline(data)
        self.numeric = extract_numeric(data)
        self.id = ""  # assigned later (D1, D2, ...)

    @property
    def browser(self):
        return self.baseline["base.browser"]


def load_reports(paths) -> list:
    files = []
    for p in map(Path, paths):
        p = p.expanduser()
        if p.is_dir():
            files.extend(sorted(p.glob("*.json")))
        elif p.exists():
            files.append(p)
        else:
            print(f"warning: {p} not found", file=sys.stderr)
    reports = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"warning: skipping {f}: {e}", file=sys.stderr)
            continue
        if not isinstance(data, dict) or (data.get("meta") or {}).get("poc") != POC_ID:
            print(f"warning: skipping {f}: not a local_model.html report", file=sys.stderr)
            continue
        reports.append(Report(f, data))
    return reports


def dedupe_by_label(reports) -> list:
    latest = {}
    for r in reports:
        if r.label not in latest or r.collected_at > latest[r.label].collected_at:
            latest[r.label] = r
    return [r for r in reports if latest[r.label] is r]


# ---------------------------------------------------------------------------- analysis
def group_keys(feature_names, prefixes):
    return sorted(k for k in feature_names if k.startswith(prefixes))


def joint_value(r: Report, keys, use_baseline=False):
    src = r.baseline if use_baseline else r.features
    return tuple(src.get(k, MISSING) for k in keys)


def anonymity_summary(values):
    sizes = Counter(values).values()
    return {
        "distinct": len(sizes),
        "unique": sum(1 for s in sizes if s == 1),
        "largest": max(sizes) if sizes else 0,
    }


def report_entropy(devices):
    n = len(devices)
    feat_names = sorted({k for r in devices for k in r.features})
    base_names = sorted({k for r in devices for k in r.baseline})
    passive = group_keys(feat_names, PASSIVE_PREFIXES)
    active = group_keys(feat_names, ACTIVE_PREFIXES)

    def h_of(keys, baseline_keys=()):
        vals = [joint_value(r, keys) + joint_value(r, baseline_keys, use_baseline=True) for r in devices]
        return entropy(vals), anonymity_summary(vals)

    rows = []
    groups = [
        ("passive AI (no permission)", passive, ()),
        ("active AI (model present)", active, ()),
        ("all AI features", passive + active, ()),
        ("baseline: UA + hardware", (), base_names),
        ("baseline + all AI", passive + active, base_names),
    ]
    results = {}
    for name, keys, bkeys in groups:
        h, a = h_of(keys, bkeys)
        results[name] = h
        rows.append([name, f"{h:.3f}", a["distinct"], a["unique"], a["largest"]])
    # Page-computed hashes (sanity check against the flattened features above).
    for hk in ("passive", "full"):
        vals = [r.hashes.get(hk, MISSING) for r in devices]
        a = anonymity_summary(vals)
        rows.append([f"page hash: {hk}", f"{entropy(vals):.3f}", a["distinct"], a["unique"], a["largest"]])

    section(f"2. ENTROPY  (N = {n} devices, max possible = log2 N = {math.log2(n):.3f} bits)" if n > 1 else "2. ENTROPY")
    print_table(["feature group", "H (bits)", "distinct", "unique", "largest set"], rows)
    extra = results["baseline + all AI"] - results["baseline: UA + hardware"]
    extra_p = h_of(passive, base_names)[0] - results["baseline: UA + hardware"]
    print()
    print(f"Extra entropy beyond UA + hardware   H(all AI | baseline)     = {extra:.3f} bits")
    print(f"                                      H(passive AI | baseline) = {extra_p:.3f} bits")
    if n < 30:
        print("note: with few devices these are lower bounds; they cannot exceed log2 N.")


def report_anonymity_sets(devices):
    section("3. ANONYMITY SETS (devices sharing a fingerprint)")
    for hk in ("passive", "full"):
        groups = defaultdict(list)
        for r in devices:
            groups[r.hashes.get(hk, MISSING)].append(r.id)
        print(f"\n{hk} hash:")
        for h, ids in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"  {h[:16]:16}  size {len(ids):<3} {' '.join(ids)}")


def report_differing(devices, show_constant, width):
    feat_names = sorted({k for r in devices for k in r.features})
    base_names = sorted({k for r in devices for k in r.baseline})
    differing, constant = [], []
    for k in feat_names + base_names:
        src = "baseline" if k.startswith("base.") else "features"
        vals = [getattr(r, src).get(k, MISSING) for r in devices]
        (differing if len(set(vals)) > 1 else constant).append((k, vals))

    section(f"4. DIFFERING FEATURES ({len(differing)} differ, {len(constant)} identical across all devices)")
    print("Features that split the devices into the same groups are merged into one block;")
    print("each line shows that feature's value for each group, in the order of the header.")

    def partition(vals):
        # Canonical group label per device: index of the first device with that value.
        first = {}
        return tuple(first.setdefault(v, len(first)) for v in vals)

    blocks = defaultdict(list)
    for k, vals in differing:
        blocks[partition(vals)].append((k, vals))
    ordered = sorted(
        blocks.items(),
        key=lambda kv: (all(k.startswith("base.") for k, _ in kv[1]), -entropy(kv[0]), kv[1][0][0]),
    )
    for part, feats in ordered:
        groups = defaultdict(list)
        for r, g in zip(devices, part):
            groups[g].append(r.id)
        header = "  |  ".join(" ".join(ids) for _, ids in sorted(groups.items()))
        print(f"\n[{len(feats)} feature{'s' if len(feats) > 1 else ''}]  H={entropy(part):.3f} bits   split: {header}")
        name_w = min(max(len(k) for k, _ in feats), 45)
        for k, vals in feats:
            first_val = {}
            for v, g in zip(vals, part):
                first_val.setdefault(g, v)
            shown = "  |  ".join(trunc(first_val[g], max(12, width // len(groups))) for g in sorted(groups))
            print(f"    {trunc(k, name_w):{name_w}}  {shown}")

    if show_constant and constant:
        print("\nIdentical on all devices:")
        for k, vals in constant:
            print(f"    {k} = {trunc(vals[0], width)}")


def report_timing(devices):
    names = sorted({k for r in devices for k, v in r.numeric.items() if v is not None})
    section("5. TIMING (ms unless noted; not part of the hashes)")
    if not names:
        print("no numeric data")
        return
    per_device = len(devices) <= 8
    headers = ["metric"] + ([r.id for r in devices] if per_device else []) + ["min", "median", "max", "max/min"]
    rows = []
    for k in names:
        vals = [r.numeric.get(k) for r in devices]
        nums = [v for v in vals if isinstance(v, (int, float))]
        lo, hi = min(nums), max(nums)
        ratio = f"{hi / lo:.1f}x" if lo > 0 else MISSING
        row = [k] + (vals if per_device else []) + [lo, round(statistics.median(nums), 2), hi, ratio]
        rows.append(row)
    print_table(headers, rows, max_width=40)


def report_pairwise(devices):
    if len(devices) < 2 or len(devices) > 20:
        return
    section("6. PAIRWISE: number of AI features that differ between two devices")
    keys = sorted({k for r in devices for k in r.features})
    headers = [""] + [r.id for r in devices]
    rows = []
    for a in devices:
        row = [a.id]
        for b in devices:
            row.append("·" if a is b else sum(a.features.get(k, MISSING) != b.features.get(k, MISSING) for k in keys))
        rows.append(row)
    print_table(headers, rows)


def report_stability(reports, width):
    by_label = defaultdict(list)
    for r in reports:
        by_label[r.label].append(r)
    repeated = {lbl: rs for lbl, rs in by_label.items() if len(rs) > 1}
    section("7. STABILITY (same device label, multiple runs)")
    if not repeated:
        print("No device label appears in more than one file. Re-run the page on a device and")
        print("save again with the same label to measure fingerprint stability.")
        return
    for lbl, rs in sorted(repeated.items()):
        rs = sorted(rs, key=lambda r: r.collected_at)
        same = {hk: len({r.hashes.get(hk) for r in rs}) == 1 for hk in ("passive", "full")}
        print(f"\n{lbl}: {len(rs)} runs  passive hash {'STABLE' if same['passive'] else 'CHANGED'}, "
              f"full hash {'STABLE' if same['full'] else 'CHANGED'}")
        keys = sorted({k for r in rs for k in r.features})
        changed = [k for k in keys if len({r.features.get(k, MISSING) for r in rs}) > 1]
        for k in changed[:15]:
            vals = " | ".join(trunc(r.features.get(k, MISSING), 30) for r in rs)
            print(f"    {k}: {vals}")
        if len(changed) > 15:
            print(f"    … and {len(changed) - 15} more")


def write_csv(path: Path, reports):
    feat = sorted({k for r in reports for k in r.features})
    base = sorted({k for r in reports for k in r.baseline})
    num = sorted({k for r in reports for k in r.numeric})
    header = ["file", "label", "collectedAt", "hash.passive", "hash.full"] + base + feat + num
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in reports:
            w.writerow(
                [r.path.name, r.label, r.collected_at, r.hashes.get("passive"), r.hashes.get("full")]
                + [r.baseline.get(k, MISSING) for k in base]
                + [r.features.get(k, MISSING) for k in feat]
                + ["" if r.numeric.get(k) is None else r.numeric.get(k) for k in num]
            )
    print(f"\nWrote {len(reports)} rows x {len(header)} columns to {path}")


# -------------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare local_model.html fingerprint reports.")
    ap.add_argument("paths", nargs="+", help="report JSON files and/or directories containing them")
    ap.add_argument("--csv", type=Path, help="also write a wide CSV (one row per file)")
    ap.add_argument("--no-dedupe", action="store_true",
                    help="count every file as a separate device (default: latest report per label)")
    ap.add_argument("--show-constant", action="store_true", help="also list features identical on all devices")
    ap.add_argument("--width", type=int, default=70, help="max width for printed values")
    args = ap.parse_args(argv)

    reports = load_reports(args.paths)
    if not reports:
        sys.exit("No valid reports found.")
    reports.sort(key=lambda r: (r.label, r.collected_at))
    devices = reports if args.no_dedupe else dedupe_by_label(reports)
    for i, r in enumerate(devices, 1):
        r.id = f"D{i}"

    section(f"1. DEVICES ({len(devices)} devices from {len(reports)} files)")
    print_table(
        ["id", "label", "browser", "platform", "LM availability", "passive hash", "full hash", "file"],
        [
            [
                r.id,
                r.label,
                r.browser,
                r.baseline["base.platform"],
                r.features.get("avail.LanguageModel|default", MISSING),
                (r.hashes.get("passive") or MISSING)[:12],
                (r.hashes.get("full") or MISSING)[:12],
                r.path.name,
            ]
            for r in devices
        ],
        max_width=36,
    )

    if len(devices) > 1:
        report_entropy(devices)
        report_anonymity_sets(devices)
        report_differing(devices, args.show_constant, args.width)
        report_timing(devices)
        report_pairwise(devices)
    else:
        print("\nOnly one device: nothing to compare across devices.")
        report_timing(devices)
    report_stability(reports, args.width)

    if args.csv:
        write_csv(args.csv, reports)


if __name__ == "__main__":
    main()
