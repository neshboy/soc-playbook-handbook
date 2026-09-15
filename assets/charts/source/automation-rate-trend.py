"""
Chart: Percentage of Triage Steps Automated Over Time
Part 26 - Automation

IMPORTANT: The data below is entirely invented for teaching purposes. It is
NOT measured from any real SOC, tool, or engagement. It exists only to show
what an "automation rate over time" trend line looks like and how to read it.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA - invented for illustration only, not real SOC data
# ---------------------------------------------------------------------------
quarters = ["Q1 2025", "Q2 2025", "Q3 2025", "Q4 2025", "Q1 2026", "Q2 2026"]
pct_automated = [15, 23, 33, 41, 49, 55]

# ---------------------------------------------------------------------------
# Palette (reference dataviz palette, light mode)
# ---------------------------------------------------------------------------
COLOR_SURFACE = "#fcfcfb"
COLOR_LINE = "#2a78d6"        # categorical slot 1 (blue) - single series
COLOR_PRIMARY_INK = "#0b0b0b"
COLOR_SECONDARY_INK = "#52514e"
COLOR_MUTED = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_BASELINE = "#c3c2b7"

fig, ax = plt.subplots(figsize=(9, 5.5), dpi=150)
fig.patch.set_facecolor(COLOR_SURFACE)
ax.set_facecolor(COLOR_SURFACE)

x = range(len(quarters))

# Horizontal gridlines only, recessive, behind the data
ax.yaxis.grid(True, color=COLOR_GRID, linewidth=1, linestyle="-", zorder=0)
ax.xaxis.grid(False)
ax.set_axisbelow(True)

# The line - 2px, round joins/caps, single series (no legend needed)
ax.plot(
    x,
    pct_automated,
    color=COLOR_LINE,
    linewidth=2.5,
    solid_joinstyle="round",
    solid_capstyle="round",
    marker="o",
    markersize=8,
    markerfacecolor=COLOR_LINE,
    markeredgecolor=COLOR_SURFACE,
    markeredgewidth=2,
    zorder=3,
)

# Direct labels: endpoints only (selective labeling, not every point)
ax.annotate(
    f"{pct_automated[0]}%",
    xy=(x[0], pct_automated[0]),
    xytext=(0, -16),
    textcoords="offset points",
    ha="center",
    va="top",
    fontsize=11,
    color=COLOR_SECONDARY_INK,
    fontweight="bold",
)
ax.annotate(
    f"{pct_automated[-1]}%",
    xy=(x[-1], pct_automated[-1]),
    xytext=(0, 12),
    textcoords="offset points",
    ha="center",
    va="bottom",
    fontsize=11,
    color=COLOR_SECONDARY_INK,
    fontweight="bold",
)

# Axes cosmetics
ax.set_xticks(list(x))
ax.set_xticklabels(quarters, color=COLOR_SECONDARY_INK, fontsize=10)

ax.set_ylim(0, 65)
ax.yaxis.set_major_locator(mticker.MultipleLocator(10))
ax.yaxis.set_major_formatter(mticker.PercentFormatter())
ax.tick_params(axis="y", colors=COLOR_MUTED, labelsize=10)
ax.tick_params(axis="x", colors=COLOR_MUTED, labelsize=10, length=0)

ax.set_ylabel(
    "% of triage steps automated", color=COLOR_SECONDARY_INK, fontsize=11
)
ax.set_xlabel("Quarter", color=COLOR_SECONDARY_INK, fontsize=11)

# Hide top/right spines; recessive baseline on the rest
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
for side in ("left", "bottom"):
    ax.spines[side].set_color(COLOR_BASELINE)
    ax.spines[side].set_linewidth(1)

# Title makes the synthetic-data status unmissable
fig.suptitle(
    "Percentage of Triage Steps Automated Over Time",
    x=0.02,
    ha="left",
    fontsize=15,
    fontweight="bold",
    color=COLOR_PRIMARY_INK,
)
ax.set_title(
    "SYNTHETIC EXAMPLE DATA - illustrative only",
    loc="left",
    fontsize=11,
    color=COLOR_MUTED,
    style="italic",
    pad=12,
)

# Footnote disclosure, restated at the bottom of the figure
fig.text(
    0.02,
    0.01,
    "SYNTHETIC EXAMPLE DATA: values are invented to illustrate the metric concept "
    "and are not measurements from any real SOC.",
    fontsize=8.5,
    color=COLOR_MUTED,
    ha="left",
)

fig.tight_layout(rect=(0, 0.05, 1, 0.94))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/automation-rate-trend.png"
fig.savefig(output_path, dpi=150, facecolor=COLOR_SURFACE)
print(f"Saved chart to {output_path}")
