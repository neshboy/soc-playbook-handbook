"""
Chart: False Positive Rate After a Tuning Pass
Part 21 - SOC Playbook Handbook

IMPORTANT: All data below is invented for illustration only. It does not come
from any real SOC, tool, or measurement. It exists purely to teach what a
"false positive rate declining after a tuning pass" trend looks like.
"""

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA - invented for teaching purposes, not real measurements
# ---------------------------------------------------------------------------
months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
false_positive_pct = [42, 35, 27, 21, 17, 14]  # made-up illustrative values

# ---------------------------------------------------------------------------
# Palette (reference dataviz palette - light mode)
# ---------------------------------------------------------------------------
COLOR_SURFACE = "#fcfcfb"
COLOR_LINE = "#2a78d6"        # categorical slot 1 / sequential hue, blue
COLOR_PRIMARY_INK = "#0b0b0b"
COLOR_SECONDARY_INK = "#52514e"
COLOR_MUTED_INK = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_BASELINE = "#c3c2b7"

fig, ax = plt.subplots(figsize=(9, 5.5), dpi=150)
fig.patch.set_facecolor(COLOR_SURFACE)
ax.set_facecolor(COLOR_SURFACE)

# Recessive gridlines behind the data
ax.set_axisbelow(True)
ax.yaxis.grid(True, color=COLOR_GRID, linewidth=1, linestyle="-")
ax.xaxis.grid(False)

# The line + markers
ax.plot(
    months,
    false_positive_pct,
    color=COLOR_LINE,
    linewidth=2,
    marker="o",
    markersize=9,
    markerfacecolor=COLOR_LINE,
    markeredgecolor=COLOR_SURFACE,
    markeredgewidth=1.5,
    solid_capstyle="round",
    zorder=3,
)

# Direct value labels above each point (selective - every point, since there
# are only 6 and the line is the whole story)
for x, y in zip(months, false_positive_pct):
    ax.annotate(
        f"{y}%",
        xy=(x, y),
        xytext=(0, 10),
        textcoords="offset points",
        ha="center",
        fontsize=10,
        color=COLOR_SECONDARY_INK,
        fontfamily="sans-serif",
    )

# Axis labels
ax.set_xlabel("Month", fontsize=11, color=COLOR_SECONDARY_INK, labelpad=10)
ax.set_ylabel("False Positive Rate (%)", fontsize=11, color=COLOR_SECONDARY_INK, labelpad=10)

# Y-axis formatting
ax.set_ylim(0, 48)
ax.yaxis.set_major_formatter(mticker.PercentFormatter(decimals=0))
ax.tick_params(axis="both", colors=COLOR_MUTED_INK, labelsize=10)

# Baseline / spine styling - hide top & right, keep bottom as a subtle baseline
for spine_name, spine in ax.spines.items():
    if spine_name in ("top", "right"):
        spine.set_visible(False)
    else:
        spine.set_color(COLOR_BASELINE)
        spine.set_linewidth(1)

# Title (includes required synthetic-data disclosure) + subtitle
fig.suptitle(
    "False Positive Rate After a Tuning Pass  (SYNTHETIC EXAMPLE DATA)",
    fontsize=14,
    fontweight="bold",
    color=COLOR_PRIMARY_INK,
    y=0.98,
)
ax.set_title(
    "Illustrative six-month trend, Jan-Jun, following an alert-tuning pass",
    fontsize=10.5,
    color=COLOR_SECONDARY_INK,
    pad=14,
)

# Footnote - explicit, on-chart disclosure that this is not real data
fig.text(
    0.5,
    0.01,
    "SYNTHETIC EXAMPLE DATA - invented figures for teaching purposes only; "
    "not measurements from any real SOC.",
    ha="center",
    fontsize=8.5,
    color=COLOR_MUTED_INK,
    style="italic",
)

fig.tight_layout(rect=(0, 0.04, 1, 0.94))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/fp-rate-trend.png"
fig.savefig(output_path, dpi=150, facecolor=COLOR_SURFACE)
print(f"Saved chart to {output_path}")
