"""
SLA Compliance Trend chart -- Part 28 Metrics, SOC Playbook Handbook.

IMPORTANT: All data in this script is SYNTHETIC EXAMPLE DATA, invented purely
to illustrate what a "SLA compliance % trend over 12 months" metric chart
looks like. It is NOT pulled from any real SOC's ticketing/SLA system and
must never be presented or reused as an actual measurement.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA -- hand-invented, not real measurements.
# 12 months of SLA compliance %, deliberately noisy month-to-month
# (no smoothing / no monotonic trend) but hovering within an 82-96% band.
# ---------------------------------------------------------------------------
months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

sla_compliance_pct = [
    91.0, 87.5, 94.0, 89.5, 83.0, 92.5,
    95.5, 86.0, 90.0, 82.5, 88.0, 93.5,
]

sla_target_pct = 90.0  # a common contractual/internal SLA target, for reference only

# ---------------------------------------------------------------------------
# Palette (validated reference palette, light mode)
# ---------------------------------------------------------------------------
COLOR_LINE = "#2a78d6"       # categorical slot 1 (blue)
COLOR_TARGET = "#898781"     # muted, for the reference target line
COLOR_PRIMARY_INK = "#0b0b0b"
COLOR_SECONDARY_INK = "#52514e"
COLOR_MUTED_INK = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_BASELINE = "#c3c2b7"
COLOR_SURFACE = "#fcfcfb"

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = [
    "Segoe UI", "DejaVu Sans", "Arial", "sans-serif",
]

fig, ax = plt.subplots(figsize=(9, 5.2), dpi=150)
fig.patch.set_facecolor(COLOR_SURFACE)
ax.set_facecolor(COLOR_SURFACE)

x = list(range(len(months)))

# Reference target line (drawn first, sits behind the data line)
ax.axhline(
    sla_target_pct,
    color=COLOR_TARGET,
    linewidth=1.25,
    linestyle=(0, (5, 4)),
    zorder=2,
)
ax.text(
    len(months) - 1 + 0.15,
    sla_target_pct,
    f"{sla_target_pct:.0f}% target",
    color=COLOR_SECONDARY_INK,
    fontsize=9,
    va="center",
    ha="left",
)

# Main SLA compliance line -- thin line, visible round markers, no smoothing
ax.plot(
    x,
    sla_compliance_pct,
    color=COLOR_LINE,
    linewidth=2,
    marker="o",
    markersize=6,
    markerfacecolor=COLOR_LINE,
    markeredgecolor=COLOR_SURFACE,
    markeredgewidth=1.2,
    solid_capstyle="round",
    zorder=3,
)

# Direct-label every point's value (small series, selective labeling is fine)
for xi, yi in zip(x, sla_compliance_pct):
    ax.annotate(
        f"{yi:.1f}",
        (xi, yi),
        textcoords="offset points",
        xytext=(0, 9),
        ha="center",
        fontsize=8,
        color=COLOR_SECONDARY_INK,
    )

# Axes cosmetics
ax.set_xticks(x)
ax.set_xticklabels(months, color=COLOR_MUTED_INK, fontsize=10)
ax.set_ylim(78, 99)
ax.yaxis.set_major_locator(mticker.MultipleLocator(4))
ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%d%%"))
ax.tick_params(axis="y", colors=COLOR_MUTED_INK, labelsize=10)
ax.tick_params(axis="x", length=0)
ax.tick_params(axis="y", length=0)

ax.set_ylabel("SLA compliance (%)", color=COLOR_SECONDARY_INK, fontsize=11)
ax.set_xlabel("Month", color=COLOR_SECONDARY_INK, fontsize=11)

# Recessive gridlines (horizontal only), hairline baseline
ax.grid(axis="y", color=COLOR_GRID, linewidth=0.9, zorder=0)
ax.grid(axis="x", visible=False)
ax.set_axisbelow(True)

for spine_name in ("top", "right"):
    ax.spines[spine_name].set_visible(False)
for spine_name in ("left", "bottom"):
    ax.spines[spine_name].set_color(COLOR_BASELINE)
    ax.spines[spine_name].set_linewidth(1)

# Title -- explicitly flags synthetic data, per handbook requirement
fig.suptitle(
    "SLA Compliance Trend \u2014 SYNTHETIC EXAMPLE DATA",
    fontsize=15,
    fontweight="bold",
    color=COLOR_PRIMARY_INK,
    x=0.02,
    ha="left",
    y=0.98,
)
ax.set_title(
    "12-month illustrative view of monthly SLA compliance %, for teaching the metric only",
    fontsize=10.5,
    color=COLOR_SECONDARY_INK,
    loc="left",
    pad=12,
)

# Footnote disclosure -- second, unmissable confirmation on the chart itself
fig.text(
    0.02,
    0.01,
    "SYNTHETIC EXAMPLE DATA \u2014 illustrative values invented to teach the SLA compliance metric. "
    "Not real measurements from any actual SOC.",
    fontsize=8.5,
    color=COLOR_MUTED_INK,
    ha="left",
    va="bottom",
    style="italic",
)

fig.tight_layout(rect=(0, 0.035, 1, 0.90))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/sla-compliance-trend.png"
fig.savefig(output_path, dpi=150, facecolor=COLOR_SURFACE)
print(f"Saved chart to {output_path}")
