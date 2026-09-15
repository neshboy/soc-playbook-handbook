"""
Weekly Alert Volume Before and After Tuning
Part 21 - SOC Playbook Handbook

SYNTHETIC EXAMPLE DATA — the numbers below are invented for illustration
only. They do not come from any real SOC, tool, or measurement; they exist
solely to teach the concept of measuring alert-tuning impact.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA (plain Python lists — invented for this handbook)
# ---------------------------------------------------------------------------
categories = ["Identity", "Endpoint", "Network", "Email"]
before_tuning = [420, 650, 800, 340]   # weekly alert count, invented
after_tuning = [180, 310, 420, 150]    # weekly alert count, invented

# ---------------------------------------------------------------------------
# Palette (validated categorical slots 1 & 2, adjacent-pair CVD check passed)
# ---------------------------------------------------------------------------
COLOR_BEFORE = "#2a78d6"   # categorical slot 1 - blue
COLOR_AFTER = "#eb6834"    # categorical slot 2 - orange

SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Segoe UI", "DejaVu Sans", "Arial", "sans-serif"]

fig, ax = plt.subplots(figsize=(9, 6), dpi=150)
fig.patch.set_facecolor(SURFACE)
ax.set_facecolor(SURFACE)

x = np.arange(len(categories))
bar_width = 0.34
gap = 0.02  # small surface gap between the paired bars

bars_before = ax.bar(
    x - bar_width / 2 - gap / 2,
    before_tuning,
    width=bar_width,
    color=COLOR_BEFORE,
    label="Before Tuning",
    zorder=3,
)
bars_after = ax.bar(
    x + bar_width / 2 + gap / 2,
    after_tuning,
    width=bar_width,
    color=COLOR_AFTER,
    label="After Tuning",
    zorder=3,
)

# Direct value labels at the tip of each bar
for bars in (bars_before, bars_after):
    for rect in bars:
        height = rect.get_height()
        ax.text(
            rect.get_x() + rect.get_width() / 2,
            height + 14,
            f"{height:,}",
            ha="center",
            va="bottom",
            fontsize=10,
            color=INK_SECONDARY,
        )

# ---------------------------------------------------------------------------
# Axes, gridlines, spines
# ---------------------------------------------------------------------------
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=11.5, color=INK_PRIMARY)
ax.tick_params(axis="x", length=0)

ax.set_ylabel("Weekly alert count", fontsize=11, color=INK_SECONDARY)
ax.set_ylim(0, 900)
ax.yaxis.set_major_locator(mticker.MultipleLocator(150))
ax.yaxis.set_major_formatter(mticker.StrMethodFormatter("{x:,.0f}"))
ax.tick_params(axis="y", labelsize=10, colors=INK_MUTED, length=0)

ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
ax.set_axisbelow(True)

ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.spines["left"].set_visible(False)
ax.spines["bottom"].set_color(BASELINE)
ax.spines["bottom"].set_linewidth(1)

# ---------------------------------------------------------------------------
# Title / subtitle / legend
# ---------------------------------------------------------------------------
ax.set_title(
    "Weekly Alert Volume Before and After Tuning\n(SYNTHETIC EXAMPLE DATA)",
    fontsize=15,
    fontweight="bold",
    color=INK_PRIMARY,
    pad=18,
)

legend = ax.legend(
    loc="upper right",
    frameon=False,
    fontsize=10.5,
    labelcolor=INK_PRIMARY,
)

# Footnote disclosure, visible directly on the chart
fig.text(
    0.5,
    0.01,
    "SYNTHETIC EXAMPLE DATA — illustrative figures invented to teach the alert-tuning metric; "
    "not measurements from any real SOC.",
    ha="center",
    va="bottom",
    fontsize=8.5,
    color=INK_MUTED,
    style="italic",
)

fig.tight_layout(rect=(0, 0.04, 1, 1))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/alert-volume-before-after-tuning.png"
fig.savefig(output_path, dpi=150, facecolor=SURFACE)
print(f"Saved chart to {output_path}")
