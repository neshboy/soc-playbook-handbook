"""
Case Rework Rate Over Time
Part 28: Metrics -- SOC Playbook Handbook

IMPORTANT: The data below is entirely SYNTHETIC / INVENTED for illustration
purposes only. It does NOT come from any real SOC, ticketing system, or
measurement. It exists solely to teach what a declining "case rework rate"
trend looks like on a chart.
"""

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA -- invented values, not real measurements.
# "Rework rate" = % of closed cases later reopened / reworked, per month.
# ---------------------------------------------------------------------------
months = ["Month 1", "Month 2", "Month 3", "Month 4", "Month 5", "Month 6"]
rework_rate_pct = [18.0, 15.5, 12.5, 10.0, 7.5, 6.0]

# ---------------------------------------------------------------------------
# Palette (validated categorical slot 1 / chrome tokens -- light mode)
# ---------------------------------------------------------------------------
COLOR_SERIES   = "#2a78d6"   # categorical slot 1 (blue)
COLOR_SURFACE  = "#fcfcfb"   # chart surface
COLOR_INK      = "#0b0b0b"   # primary ink (title)
COLOR_INK_2    = "#52514e"   # secondary ink (subtitle / footnote)
COLOR_MUTED    = "#898781"   # muted (axis ticks/labels)
COLOR_GRID     = "#e1e0d9"   # hairline gridline
COLOR_BASELINE = "#c3c2b7"   # baseline / axis line

fig, ax = plt.subplots(figsize=(9, 5.2), dpi=150)
fig.patch.set_facecolor(COLOR_SURFACE)
ax.set_facecolor(COLOR_SURFACE)

# Recessive gridlines (horizontal only), behind the data
ax.yaxis.grid(True, color=COLOR_GRID, linewidth=1, zorder=0)
ax.set_axisbelow(True)

# The line: 2px, rounded ends/joins, single series -> no legend needed
ax.plot(
    months,
    rework_rate_pct,
    color=COLOR_SERIES,
    linewidth=2.5,
    marker="o",
    markersize=8,
    markerfacecolor=COLOR_SERIES,
    markeredgecolor=COLOR_SURFACE,
    markeredgewidth=1.5,
    solid_capstyle="round",
    solid_joinstyle="round",
    zorder=3,
)

# Direct value labels above each point (selective but here every point,
# since there are only 6 and the series has no legend to lean on)
for x, y in zip(months, rework_rate_pct):
    ax.annotate(
        f"{y:.1f}%",
        xy=(x, y),
        xytext=(0, 10),
        textcoords="offset points",
        ha="center",
        fontsize=10,
        color=COLOR_INK,
        fontweight="bold",
    )

# Axes cosmetics: hide top/right spines, mute the rest
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
for side in ("left", "bottom"):
    ax.spines[side].set_color(COLOR_BASELINE)

ax.tick_params(axis="x", colors=COLOR_MUTED, labelsize=10)
ax.tick_params(axis="y", colors=COLOR_MUTED, labelsize=10)

ax.yaxis.set_major_formatter(mticker.PercentFormatter(decimals=0))
ax.set_ylim(0, 22)
ax.set_ylabel("Closed cases later reopened / reworked (%)", color=COLOR_INK_2, fontsize=11)
ax.set_xlabel("Month", color=COLOR_INK_2, fontsize=11)

# Title includes the required synthetic-data disclosure
ax.set_title(
    "Case Rework Rate Over Time  (SYNTHETIC EXAMPLE DATA)",
    color=COLOR_INK,
    fontsize=15,
    fontweight="bold",
    pad=18,
)

# Belt-and-suspenders disclosure as an on-chart footnote as well
fig.text(
    0.5,
    0.02,
    "SYNTHETIC EXAMPLE DATA -- illustrative values invented to teach the metric; not measurements from any real SOC.",
    ha="center",
    va="bottom",
    fontsize=8.5,
    color=COLOR_INK_2,
    style="italic",
)

fig.tight_layout(rect=(0, 0.05, 1, 1))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/analyst-rework-rate.png"
fig.savefig(output_path, dpi=150, facecolor=COLOR_SURFACE)
print(f"Saved chart to {output_path}")
