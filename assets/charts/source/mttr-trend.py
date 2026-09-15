"""
MTTR Trend by Quarter -- SOC Playbook Handbook, Part 28 (Metrics)

IMPORTANT: The data below is entirely INVENTED for illustration purposes.
It does not come from any real SOC, ticketing system, or measurement.
It exists only to show what a "Mean Time to Respond, trending down over
time, with realistic noise" chart looks like.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA -- hand-picked, not measured. Two illustrative years
# of quarterly Mean Time to Respond (MTTR), in hours, with a gradual downward
# trend plus realistic quarter-to-quarter noise (not a perfectly smooth line).
# ---------------------------------------------------------------------------
quarters = [
    "Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024",
    "Q1 2025", "Q2 2025", "Q3 2025", "Q4 2025",
]
mttr_hours = [
    6.2, 5.8, 6.0, 5.4,
    5.1, 5.3, 4.6, 4.3,
]

# ---------------------------------------------------------------------------
# Palette (dataviz skill reference palette, light mode)
# ---------------------------------------------------------------------------
SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"
SERIES_BLUE = "#2a78d6"

fig, ax = plt.subplots(figsize=(9, 5.2), dpi=150)
fig.patch.set_facecolor(SURFACE)
ax.set_facecolor(SURFACE)

x = list(range(len(quarters)))

# Recessive horizontal gridlines first (drawn under the data)
ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, linestyle="-", zorder=0)
ax.set_axisbelow(True)

# The line itself: 2px, round joins/caps, single series
ax.plot(
    x,
    mttr_hours,
    color=SERIES_BLUE,
    linewidth=2,
    solid_capstyle="round",
    solid_joinstyle="round",
    zorder=3,
)

# Markers: >=8px diameter, filled with the series color, 2px surface ring
ax.plot(
    x,
    mttr_hours,
    marker="o",
    markersize=8,
    markerfacecolor=SERIES_BLUE,
    markeredgecolor=SURFACE,
    markeredgewidth=2,
    linestyle="none",
    zorder=4,
)

# Direct label at the endpoint only (selective labeling, not every point)
ax.annotate(
    f"{mttr_hours[-1]:.1f}h",
    xy=(x[-1], mttr_hours[-1]),
    xytext=(10, 4),
    textcoords="offset points",
    fontsize=11,
    fontweight="bold",
    color=INK_PRIMARY,
)
ax.annotate(
    f"{mttr_hours[0]:.1f}h",
    xy=(x[0], mttr_hours[0]),
    xytext=(-8, 10),
    textcoords="offset points",
    fontsize=11,
    fontweight="bold",
    color=INK_SECONDARY,
    ha="right",
)

# Axes cosmetics: hide top/right spines, recede the rest
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
for side in ("left", "bottom"):
    ax.spines[side].set_color(BASELINE)
    ax.spines[side].set_linewidth(1)

ax.set_xticks(x)
ax.set_xticklabels(quarters, color=INK_MUTED, fontsize=10)
ax.tick_params(axis="x", length=0)
ax.tick_params(axis="y", colors=INK_MUTED, length=0, labelsize=10)

ax.yaxis.set_major_locator(mticker.MultipleLocator(1))
ax.set_ylim(0, max(mttr_hours) + 1.5)
ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.0fh"))

ax.set_ylabel("Mean Time to Respond (hours)", color=INK_SECONDARY, fontsize=11)

# Title makes the synthetic nature unmissable, plus a footnote repeats it
ax.set_title(
    "MTTR Trend by Quarter -- SYNTHETIC EXAMPLE DATA",
    color=INK_PRIMARY,
    fontsize=14,
    fontweight="bold",
    pad=16,
)

fig.text(
    0.01,
    0.01,
    "SYNTHETIC EXAMPLE DATA -- illustrative values invented to demonstrate the metric; "
    "not measurements from any real SOC.",
    fontsize=8.5,
    color=INK_MUTED,
    ha="left",
    va="bottom",
)

fig.tight_layout(rect=(0, 0.05, 1, 1))

out_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/mttr-trend.png"
fig.savefig(out_path, dpi=150, facecolor=SURFACE)
print(f"Saved chart to {out_path}")
