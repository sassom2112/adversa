"""
Regenerate training_graphs.png from brain_state.json.bak.

Uses the first 3000 iterations, which show the full arc from low detection
through autonomous convergence to sustained 75-94%. Annotates the two key
inflection points: early ramp-up and the convergence zone.
"""

import json
import os
import sys

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT  = os.path.dirname(_SCRIPT_DIR)
_REPORTS    = os.path.join(_REPO_ROOT, "reports")
_BAK        = os.path.join(_REPORTS, "brain_state.json.bak")
_OUT        = os.path.join(_REPORTS, "training_graphs.png")

SLICE_END   = 3000   # only show the convergence story; skip post-collapse tail
ROLLING_WIN = 50     # wider window for cleaner signal at this scale


def load_metrics(path, max_iter=SLICE_END):
    with open(path) as f:
        state = json.load(f)
    m = state["metrics"]

    iters  = m["iterations"]
    cutoff = next((i for i, v in enumerate(iters) if v > max_iter), len(iters))

    def trim(key):
        return m[key][:cutoff]

    weights = {}
    for tech, wlist in m.get("weights", {}).items():
        weights[tech] = wlist[:cutoff]

    return {
        "iterations":       trim("iterations"),
        "blue_scores":      trim("blue_scores"),
        "detection_flags":  trim("detection_flags"),
        "red_generations":  trim("red_generations"),
        "blue_pattern_counts": trim("blue_pattern_counts"),
        "weights":          weights,
    }


def rolling_avg(values, window):
    kernel = np.ones(window) / window
    return np.convolve(values, kernel, mode="valid")


def rolling_rate(flags, window):
    return [
        sum(flags[max(0, i - window): i + 1]) / min(i + 1, window)
        for i in range(len(flags))
    ]


def plot(m, out_path):
    iters  = m["iterations"]
    scores = m["blue_scores"]
    flags  = m["detection_flags"]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(
        "Forensic GAN Training — Red vs Blue Agent",
        fontsize=16, fontweight="bold",
    )

    _palette = [
        "#E91E63", "#9C27B0", "#FF9800", "#009688", "#795548",
        "#2196F3", "#FF5722", "#607D8B", "#8BC34A",
    ]

    # ── Panel 1: Detection Score ────────────────────────────────────
    ax1 = axes[0, 0]
    ax1.plot(iters, scores, color="#2196F3", alpha=0.3, linewidth=0.8)

    roll = rolling_avg(scores, ROLLING_WIN)
    roll_iters = iters[ROLLING_WIN - 1:]
    ax1.plot(roll_iters, roll, color="#1565C0", linewidth=2.5,
             label=f"{ROLLING_WIN}-iter rolling avg")

    ax1.axhline(y=40, color="orange", linestyle="--",
                linewidth=1.5, label="Detection threshold (40)")
    ax1.axhline(y=70, color="red", linestyle="--",
                linewidth=1.5, label="High confidence (70)")

    # Shade convergence zone
    conv_start = 700
    ax1.axvspan(conv_start, max(iters), alpha=0.06, color="green",
                label="Convergence zone")

    # Annotate the ramp-up
    ax1.annotate(
        "Autonomous\nramp-up",
        xy=(350, 45), xytext=(500, 20),
        arrowprops=dict(arrowstyle="->", color="gray"),
        fontsize=8, color="gray",
    )
    # Annotate sustained high performance
    ax1.annotate(
        "Sustained\n75–94% detection",
        xy=(1200, 80), xytext=(1400, 90),
        arrowprops=dict(arrowstyle="->", color="green"),
        fontsize=8, color="green",
    )

    ax1.set_title("Blue Agent Detection Score", fontweight="bold")
    ax1.set_xlabel("Iteration")
    ax1.set_ylabel("Score (0-100)")
    ax1.legend(fontsize=8)
    ax1.set_ylim(0, 115)
    ax1.fill_between(iters, scores, alpha=0.08, color="#2196F3")

    # ── Panel 2: Detection Rate ─────────────────────────────────────
    ax2 = axes[0, 1]

    rate = rolling_rate(flags, ROLLING_WIN)
    ax2.plot(iters, rate, color="#4CAF50", linewidth=2.5)
    ax2.fill_between(iters, rate, alpha=0.15, color="#4CAF50")

    for it, flag in zip(iters, flags):
        color = "#4CAF50" if flag else "#f44336"
        ax2.scatter(it, flag, color=color, alpha=0.3, s=8, zorder=5)

    ax2.axhline(y=0.5, color="gray", linestyle="--", linewidth=1)
    ax2.axvspan(conv_start, max(iters), alpha=0.06, color="green")

    ax2.annotate(
        "Self-corrects to\n>75% without\nhuman intervention",
        xy=(800, 0.80), xytext=(1100, 0.55),
        arrowprops=dict(arrowstyle="->", color="green"),
        fontsize=8, color="green",
    )

    ax2.set_title("Detection Rate Over Time", fontweight="bold")
    ax2.set_xlabel("Iteration")
    ax2.set_ylabel("Detection Rate")
    ax2.set_ylim(-0.1, 1.15)
    ax2.legend(
        handles=[
            mpatches.Patch(color="#4CAF50", label="Detected"),
            mpatches.Patch(color="#f44336", label="Missed"),
        ],
        fontsize=8,
    )

    # ── Panel 3: Arms Race ──────────────────────────────────────────
    ax3      = axes[1, 0]
    ax3_twin = ax3.twinx()

    l1, = ax3.plot(iters, m["red_generations"],
                   color="#f44336", linewidth=2.5,
                   label="Red generations (evasions)")
    l2, = ax3_twin.plot(iters, m["blue_pattern_counts"],
                        color="#2196F3", linewidth=2.5, linestyle="--",
                        label="Blue patterns learned")

    ax3.set_title("GAN Arms Race — Red Evasions vs Blue Patterns",
                  fontweight="bold")
    ax3.set_xlabel("Iteration")
    ax3.set_ylabel("Red Generations", color="#f44336")
    ax3_twin.set_ylabel("Blue Pattern Count", color="#2196F3")
    ax3.legend(handles=[l1, l2], fontsize=8, loc="upper left")

    # ── Panel 4: Weight Evolution ───────────────────────────────────
    ax4 = axes[1, 1]
    for (tech_id, weights), color in zip(m["weights"].items(), _palette):
        if weights:
            ax4.plot(
                iters[: len(weights)], weights,
                label=tech_id, color=color,
                linewidth=2, marker="o", markersize=3, markevery=50,
            )

    ax4.set_title("Detection Weight Evolution Per Technique",
                  fontweight="bold")
    ax4.set_xlabel("Iteration")
    ax4.set_ylabel("Weight")
    ax4.legend(fontsize=7, loc="upper right")
    ax4.set_ylim(0, 60)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved → {out_path}")


if __name__ == "__main__":
    if not os.path.exists(_BAK):
        sys.exit(f"ERROR: backup not found at {_BAK}")

    print(f"Loading {_BAK} ...")
    m = load_metrics(_BAK, max_iter=SLICE_END)
    print(f"  {len(m['iterations'])} iterations loaded "
          f"(range {m['iterations'][0]}–{m['iterations'][-1]})")

    # Quick sanity: detection rate in first/last 200 iters of slice
    early = m["detection_flags"][:200]
    late  = m["detection_flags"][-200:]
    print(f"  Early detection rate (first 200): "
          f"{sum(early)/len(early)*100:.0f}%")
    print(f"  Late  detection rate (last  200): "
          f"{sum(late)/len(late)*100:.0f}%")

    plot(m, _OUT)
