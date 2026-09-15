"""
Escalation Rate by Playbook Category — SOC Playbook Handbook, Part 23.

SYNTHETIC EXAMPLE DATA: the numbers below are invented purely to illustrate
the "escalation rate" metric concept. They are NOT measurements from any
real SOC, vendor, or dataset.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA (invented for illustration only — not real SOC data)
# ---------------------------------------------------------------------------
categories = [
    "Insider Threat",
    "AI Security",
    "Cloud",
    "Identity",
    "Network",
    "Email",
    "Endpoint",
]
escalation_rate_pct = [
    41,
    36,
    29,
    24,
    18,
    12,
    8,
]

# Sort ascending so the largest bar renders at the top of a horizontal chart
order = sorted(range(len(categories)), key=lambda i: escalation_rate_pct[i])
categories = [categories[i] for i in order]
escalation_rate_pct = [escalation_rate_pct[i] for i in order]

# ---------------------------------------------------------------------------
# Palette (validated categorical slot 1 / sequential hue — see dataviz skill)
# ---------------------------------------------------------------------------
BAR_COLOR = "#2a78d6"          # blue, categorical slot 1
SURFACE = "#fcfcfb"            # chart surface
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"

fig, ax = plt.subplots(figsize=(9, 5.2), dpi=150)
fig.patch.set_facecolor(SURFACE)
ax.set_facecolor(SURFACE)

bar_height = 0.55
y_positions = range(len(categories))

bars = ax.barh(
    y_positions,
    escalation_rate_pct,
    height=bar_height,
    color=BAR_COLOR,
    edgecolor="none",
    zorder=3,
)

# Value labels at the tip of each bar
for y, value in zip(y_positions, escalation_rate_pct):
    ax.text(
        value + 0.8,
        y,
        f"{value}%",
        va="center",
        ha="left",
        fontsize=11,
        color=INK_PRIMARY,
        fontweight="normal",
    )

# Axes cosmetics
ax.set_yticks(list(y_positions))
ax.set_yticklabels(categories, fontsize=11, color=INK_PRIMARY)
ax.set_xlim(0, max(escalation_rate_pct) + 8)
ax.set_xlabel("Escalation rate (%)", fontsize=11, color=INK_SECONDARY, labelpad=10)

ax.xaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
ax.set_axisbelow(True)

# Hide top/right/left spines; keep a recessive bottom baseline
for spine_name in ("top", "right", "left"):
    ax.spines[spine_name].set_visible(False)
ax.spines["bottom"].set_color(BASELINE)
ax.spines["bottom"].set_linewidth(1)

ax.tick_params(axis="y", length=0)
ax.tick_params(axis="x", length=0, colors=INK_MUTED, labelsize=10)

# Title (includes SYNTHETIC EXAMPLE DATA disclosure)
fig.suptitle(
    "Escalation Rate by Playbook Category",
    fontsize=15,
    fontweight="bold",
    color=INK_PRIMARY,
    x=0.02,
    ha="left",
    y=0.98,
)
ax.set_title(
    "SYNTHETIC EXAMPLE DATA — illustrative figures only, not real SOC measurements",
    fontsize=10.5,
    color=INK_SECONDARY,
    style="italic",
    loc="left",
    pad=14,
)

# Footnote reinforcing the synthetic-data disclosure directly on the chart
fig.text(
    0.02,
    0.02,
    "Note: All values are fabricated for teaching purposes (SOC Playbook Handbook, Part 23) "
    "and do not represent any actual organization's data.",
    fontsize=8.5,
    color=INK_MUTED,
    ha="left",
    va="bottom",
)

plt.tight_layout(rect=(0, 0.06, 1, 0.94))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/escalation-rate-by-category.png"
fig.savefig(output_path, dpi=150, facecolor=SURFACE)
print(f"Saved chart to {output_path}")
