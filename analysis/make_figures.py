"""Figures for the IC4 paper, at print size for one IEEE column (3.5 in), Times text.
   python analysis/make_figures.py      (writes figs/fig1_flow.png, figs/fig2_proving.png and .pdf)
"""
import json
from collections import defaultdict
from pathlib import Path
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Patch

ROOT = Path(__file__).resolve().parents[1]
FIGS = ROOT / "figs"
FIGS.mkdir(exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"], "font.size": 8,
                     "mathtext.fontset": "stix", "axes.linewidth": 0.6, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
                     "savefig.dpi": 600})


def save(fig, name):
    # no software or date metadata, so a rerun with the same Matplotlib writes the same bytes
    fig.savefig(FIGS / f"{name}.png", bbox_inches="tight", pad_inches=0.02, metadata={"Software": None})
    fig.savefig(FIGS / f"{name}.pdf", bbox_inches="tight", pad_inches=0.02, metadata={"Creator": None, "Producer": None, "CreationDate": None})
    plt.close(fig)


# Fig. 1: actors and message flow
def fig_flow():
    fig, ax = plt.subplots(figsize=(3.5, 2.45))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 70)
    ax.axis("off")
    boxes = [(1, 46, 35, 22, "Issuer (platform)\ndid:ethr, enrollment,\ncredential tree"),
             (64, 46, 35, 22, "L1 or rollup\nERC-1056, root registry\n(16-root ring, events)"),
             (1, 2, 35, 22, "Member\nsecret s, VC 2.0,\npath rebuilt from log"),
             (64, 2, 35, 22, "Community verifier\nanchored policy,\nnullifier table")]
    for x, y, w, h, t in boxes:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5,rounding_size=2", fc="#f2f2f2", ec="black", lw=0.6))
        ax.text(x + w / 2, y + h / 2, t, ha="center", va="center", fontsize=7, linespacing=1.15)
    kw = dict(arrowstyle="-|>", mutation_scale=7, lw=0.6, color="black")
    lab = dict(fontsize=6.5, ha="center", va="center", linespacing=1.1)
    ax.add_patch(FancyArrowPatch((4, 25), (4, 45), **kw))          # (1) holder -> issuer
    ax.add_patch(FancyArrowPatch((33, 45), (33, 25), **kw))        # (2) issuer -> holder
    ax.text(18.5, 39.5, "(1) C$_{id}$ = H(s)", **lab)
    ax.text(18.5, 30.5, "(2) VC,\nleaf index", **lab)
    ax.add_patch(FancyArrowPatch((37, 57), (63, 57), **kw))        # (3) and (7) issuer -> chain
    ax.text(50, 63.5, "(3) leaves, R\n(7) revoked, R'", **lab)
    ax.add_patch(FancyArrowPatch((37, 13), (63, 13), **kw))        # (4) holder -> verifier
    ax.text(50, 18.5, r"(4) post, $\pi$, y, $\phi$, $\psi$", **lab)
    ax.add_patch(FancyArrowPatch((81.5, 25), (81.5, 45), **kw))    # (5) verifier -> chain
    ax.text(83, 35, "(5) policy,\nR in window?", fontsize=6.5, ha="left", va="center", linespacing=1.1)
    ax.add_patch(FancyArrowPatch((66, 25), (36, 46), **kw))        # (6) verifier -> issuer
    ax.text(51, 35.5, "(6) over limit:\n" + r"s, C$_{id}$", bbox=dict(fc="white", ec="none", pad=0.6), **lab)
    save(fig, "fig1_flow")


# Fig. 2: proving time against tree depth, with the reference RLN v2 circuit
def fig_proving():
    session = json.loads((ROOT / "data" / "paper_numbers.json").read_text(encoding="utf-8"))["bench.session"]
    runs = defaultdict(list)
    for line in (ROOT / "data" / "bench_runs.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("session") == session and not r.get("cold"):  # warm runs of the session the paper cites
                runs[r["name"]].append(r["totalMs"] / 1000)
    info = {p.parent.name: json.loads(p.read_text(encoding="utf-8")) for p in (ROOT / "build").glob("*/info.json")}
    depths = [10, 16, 20, 24, 32]
    fig, ax = plt.subplots(figsize=(3.5, 1.9))
    pos = list(range(len(depths)))
    data = [runs[f"vcrln_d{d}"] for d in depths]
    style = dict(flierprops=dict(marker="o", ms=2, mfc="none", mew=0.5), medianprops=dict(color="black", lw=0.8),
                 whiskerprops=dict(lw=0.6), capprops=dict(lw=0.6), patch_artist=True, showfliers=True)
    ax.boxplot(data, positions=pos, widths=0.45, boxprops=dict(fc="#d9d9d9", lw=0.6), **style)
    ax.boxplot([runs["rln2_d20"]], positions=[2.45], widths=0.3, boxprops=dict(fc="white", hatch="////", lw=0.6), **style)
    ax.set_xticks(pos, [f"{d}\n{info[f'vcrln_d{d}']['constraints']:,}" for d in depths])
    ax.set_xlabel("tree depth / constraints", labelpad=1)
    ax.set_ylabel("witness + proof (s)")
    ax.set_xlim(-0.6, len(depths) - 0.4)
    top = max(max(x) for x in data + [runs["rln2_d20"]])
    ax.set_ylim(0, top * 1.12)
    ax.legend(handles=[Patch(fc="#d9d9d9", ec="black", lw=0.6, label="this design"),
                       Patch(fc="white", ec="black", lw=0.6, hatch="////", label="RLN v2, depth 20")],
              loc="upper left", fontsize=6.5, frameon=False, handlelength=1.3, handleheight=0.9, borderaxespad=0.2)
    ax.grid(axis="y", lw=0.3, alpha=0.5)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    save(fig, "fig2_proving")


if __name__ == "__main__":
    fig_flow()
    if (ROOT / "data" / "bench_runs.jsonl").exists():
        fig_proving()
    print("figures written to", FIGS)
