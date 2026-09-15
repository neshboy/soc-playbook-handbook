"""
MTTA Trend by Quarter -- Part 28 Metrics, SOC Playbook Handbook.

IMPORTANT: All data below is invented for illustration purposes only.
It is SYNTHETIC EXAMPLE DATA meant to teach the MTTA metric concept and
does NOT represent real measurements from any actual SOC.
"""

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# Synthetic data (plain Python lists, invented for this illustration only)
# ---------------------------------------------------------------------------
quarters = [
    "Y1 Q1", "Y1 Q2", "Y1 Q3", "Y1 Q4",
    "Y2 Q1", "Y2 Q2", "Y2 Q3", "Y2 Q4",
]

# Mean Time to Acknowledge, in minutes. Generally trending down (improving),
# with a deliberate slight regression in Y2 Q1 to look like a realistic,
# non-monotonic trend rather than a too-perfect straight line down.
mtta_minutes = [42, 38, 35, 31, 33, 29, 26, 23]

# ---------------------------------------------------------------------------
# Palette (dataviz skill reference palette -- light mode)
# ---------------------------------------------------------------------------
SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"
SERIES_BLUE = "#2a78d6"
STATUS_SERIOUS = "#ec835a"  # used only for the regression annotation callout

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Segoe UI", "DejaVu Sans", "Arial"]

fig, ax = plt.subplots(figsize=(9, 5.5), dpi=150)
fig.patch.set_facecolor(SURFACE)
ax.set_facecolor(SURFACE)

x = list(range(len(quarters)))

# Gridlines first (recessive, behind the data)
ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
ax.set_axisbelow(True)

# The line + markers
ax.plot(
    x,
    mtta_minutes,
    color=SERIES_BLUE,
    linewidth=2.5,
    marker="o",
    markersize=8,
    markerfacecolor=SERIES_BLUE,
    markeredgecolor=SURFACE,
    markeredgewidth=1.5,
    zorder=3,
    solid_capstyle="round",
)

# Direct value labels on each point (small series; labeling all is fine here)
for xi, yi in zip(x, mtta_minutes):
    ax.annotate(
        f"{yi}",
        (xi, yi),
        textcoords="offset points",
        xytext=(0, 12),
        ha="center",
        fontsize=9.5,
        color=INK_SECONDARY,
    )

# Callout on the one quarter that regresses (Y2 Q1), so it reads as
# intentional/realistic rather than an error in the data
regress_idx = 4
ax.annotate(
    "Y2 Q1: slight regression\n(process change under review)",
    xy=(regress_idx, mtta_minutes[regress_idx]),
    xytext=(regress_idx + 0.35, mtta_minutes[regress_idx] + 9),
    fontsize=8.5,
    color=STATUS_SERIOUS,
    ha="left",
    arrowprops=dict(arrowstyle="-", color=STATUS_SERIOUS, linewidth=1),
)

# Axes cosmetics
ax.set_xticks(x)
ax.set_xticklabels(quarters, color=INK_SECONDARY, fontsize=10)
ax.set_ylabel("Mean Time to Acknowledge (minutes)", color=INK_SECONDARY, fontsize=10.5)
ax.yaxis.set_major_locator(mticker.MultipleLocator(5))
ax.tick_params(axis="y", colors=INK_SECONDARY, labelsize=9.5)
ax.tick_params(axis="x", colors=INK_SECONDARY, labelsize=9.5, length=0)
ax.set_ylim(0, max(mtta_minutes) + 14)

# Hide top/right spines; keep bottom/left as a light baseline
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
for side in ("left", "bottom"):
    ax.spines[side].set_color(BASELINE)
    ax.spines[side].set_linewidth(1)

# Title (includes the synthetic-data disclosure directly in the title)
ax.set_title(
    "MTTA Trend by Quarter -- SYNTHETIC EXAMPLE DATA",
    color=INK_PRIMARY,
    fontsize=15,
    fontweight="bold",
    pad=18,
)

# Footnote disclosure as well, so it is visible even if the title is cropped
fig.text(
    0.01,
    0.01,
    "Illustrative synthetic data for teaching purposes only -- not measurements from any real SOC.",
    fontsize=8.5,
    color=INK_MUTED,
    ha="left",
)

fig.tight_layout(rect=(0, 0.03, 1, 1))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/mtta-trend.png"
fig.savefig(output_path, dpi=150, facecolor=SURFACE)
print(f"Saved chart to {output_path}")
