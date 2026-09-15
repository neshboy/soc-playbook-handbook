"""
Alert Volume by Severity - SYNTHETIC EXAMPLE DATA

Generates a bar chart for the SOC Playbook Handbook (Part 25) illustrating the
typical "pyramid" shape of alert volume by severity: most alerts triaged by a
SOC are low-value noise (Informational/Low), while true High/Critical events
are comparatively rare.

IMPORTANT: The numbers below are entirely fabricated for teaching purposes.
They are NOT measurements from any real SOC, tool, or customer environment.
Do not cite these figures as real-world statistics.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC data (plain Python lists) - invented to show a realistic pyramid
# shape (Informational/Low much taller than High/Critical). Not real data.
# ---------------------------------------------------------------------------
severity_levels = ["Informational", "Low", "Medium", "High", "Critical"]
alert_counts = [18400, 12600, 4200, 980, 210]  # fabricated example counts

# One-hue ordinal ramp (light -> dark = low -> high severity).
# Validated ordinal ramp: monotone lightness, single hue, light end clears
# 2:1 contrast against the chart surface.
bar_colors = ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"]

surface_color = "#fcfcfb"
primary_ink = "#0b0b0b"
secondary_ink = "#52514e"
muted_ink = "#898781"
gridline_color = "#e1e0d9"
axis_color = "#c3c2b7"

fig, ax = plt.subplots(figsize=(9, 6), dpi=150)
fig.patch.set_facecolor(surface_color)
ax.set_facecolor(surface_color)

bar_width = 0.6
x_positions = range(len(severity_levels))

bars = ax.bar(
    x_positions,
    alert_counts,
    width=bar_width,
    color=bar_colors,
    edgecolor="none",
    zorder=3,
)

# Recessive horizontal gridlines only, drawn behind the bars.
ax.set_axisbelow(True)
ax.yaxis.grid(True, color=gridline_color, linewidth=1, zorder=0)
ax.xaxis.grid(False)

# Hide top/right spines; keep a light baseline/left axis.
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
ax.spines["left"].set_color(axis_color)
ax.spines["bottom"].set_color(axis_color)

# Axis ticks and labels.
ax.set_xticks(list(x_positions))
ax.set_xticklabels(severity_levels, fontsize=11, color=primary_ink)
ax.tick_params(axis="x", length=0)
ax.tick_params(axis="y", colors=muted_ink, length=0)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
ax.set_ylim(0, max(alert_counts) * 1.18)

ax.set_xlabel("Severity Level", fontsize=11, color=secondary_ink, labelpad=10)
ax.set_ylabel("Alert Count (synthetic)", fontsize=11, color=secondary_ink, labelpad=10)

# Direct value labels at each bar tip (5 bars - sparing and readable).
for rect, value in zip(bars, alert_counts):
    ax.text(
        rect.get_x() + rect.get_width() / 2,
        rect.get_height() + max(alert_counts) * 0.015,
        f"{value:,}",
        ha="center",
        va="bottom",
        fontsize=10,
        color=primary_ink,
    )

# Title: clearly flags this as synthetic example data, per handbook requirement.
fig.suptitle(
    "Alert Volume by Severity  \u2014  SYNTHETIC EXAMPLE DATA",
    fontsize=15,
    fontweight="bold",
    color=primary_ink,
    y=0.98,
)
ax.set_title(
    "Illustrative pyramid shape: most alerts are low-severity noise",
    fontsize=11,
    color=secondary_ink,
    pad=14,
)

# Footnote disclosure, visible directly on the chart itself.
fig.text(
    0.01,
    0.01,
    "Synthetic example data for illustration only \u2014 fabricated to teach the concept, "
    "not measurements from any real SOC, tool, or environment.",
    fontsize=8.5,
    color=muted_ink,
    ha="left",
    va="bottom",
    style="italic",
)

fig.tight_layout(rect=(0, 0.035, 1, 0.94))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/severity-distribution.png"
fig.savefig(output_path, dpi=150, facecolor=surface_color)
print(f"Saved chart to {output_path}")
