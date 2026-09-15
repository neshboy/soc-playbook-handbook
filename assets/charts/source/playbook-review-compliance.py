"""
Playbook Review Compliance by Category — Part 29 Governance

Renders a bar chart showing what % of playbooks in each SOC category were
reviewed on schedule. ALL NUMBERS BELOW ARE INVENTED FOR ILLUSTRATION.
This is synthetic example data used to teach the "review compliance by
category" metric concept for the handbook — it is NOT a measurement from
any real SOC, tool, or organization.
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA — plain Python values, invented for this handbook.
# Not sourced from any real SOC's playbook review records.
# ---------------------------------------------------------------------------
categories = ["Identity", "Endpoint", "Network", "Email", "Cloud", "AI Security"]
pct_reviewed_on_schedule = [95, 92, 90, 89, 87, 64]

TARGET_PCT = 85  # illustrative governance target used for this example
BEHIND_THRESHOLD = 75  # flag as "behind" only when meaningfully under target

# Palette (validated categorical slot-1 blue; fixed status "critical" red for
# the one category that is materially behind the review target).
COLOR_ON_TRACK = "#2a78d6"
COLOR_BEHIND = "#d03b3b"
COLOR_TARGET_LINE = "#898781"
COLOR_TEXT_PRIMARY = "#0b0b0b"
COLOR_TEXT_SECONDARY = "#52514e"
COLOR_MUTED = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_SURFACE = "#fcfcfb"

bar_colors = [
    COLOR_BEHIND if v < BEHIND_THRESHOLD else COLOR_ON_TRACK
    for v in pct_reviewed_on_schedule
]

fig, ax = plt.subplots(figsize=(9, 6), dpi=150)
fig.patch.set_facecolor(COLOR_SURFACE)
ax.set_facecolor(COLOR_SURFACE)

x_positions = range(len(categories))
bars = ax.bar(
    x_positions,
    pct_reviewed_on_schedule,
    width=0.55,
    color=bar_colors,
    zorder=3,
)

# Target threshold line (a real illustrative governance target, so dashing
# here signals "threshold", not a gridline).
ax.axhline(
    TARGET_PCT,
    color=COLOR_TARGET_LINE,
    linestyle="--",
    linewidth=1.5,
    zorder=2,
)
ax.text(
    0.5,
    TARGET_PCT + 2.2,
    f"Target: {TARGET_PCT}%",
    color=COLOR_TEXT_SECONDARY,
    fontsize=10,
    ha="left",
    va="bottom",
)

# Direct value labels on top of each bar (value on the cap).
for rect, value in zip(bars, pct_reviewed_on_schedule):
    ax.text(
        rect.get_x() + rect.get_width() / 2,
        rect.get_height() + 1.5,
        f"{value}%",
        ha="center",
        va="bottom",
        fontsize=11,
        color=COLOR_TEXT_PRIMARY,
        fontweight="bold",
    )

# Callout on the lagging category.
lag_index = pct_reviewed_on_schedule.index(min(pct_reviewed_on_schedule))
ax.annotate(
    "Newest category —\nreview cadence still ramping up",
    xy=(lag_index, pct_reviewed_on_schedule[lag_index] + 4),
    xytext=(lag_index - 1.6, 40),
    fontsize=9.5,
    color=COLOR_TEXT_SECONDARY,
    ha="left",
    arrowprops=dict(arrowstyle="-", color=COLOR_MUTED, linewidth=1),
)

# Axes cosmetics
ax.set_xticks(list(x_positions))
ax.set_xticklabels(categories, fontsize=11, color=COLOR_TEXT_PRIMARY)
ax.set_ylim(0, 108)
yticks = [0, 20, 40, 60, 80, 100]
ax.set_yticks(yticks)
ax.set_yticklabels([f"{t}%" for t in yticks], fontsize=10, color=COLOR_MUTED)
ax.set_ylabel("Playbooks reviewed on schedule", fontsize=11, color=COLOR_TEXT_SECONDARY)

ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.spines["left"].set_color(COLOR_MUTED)
ax.spines["bottom"].set_color(COLOR_MUTED)

ax.yaxis.grid(True, color=COLOR_GRID, linewidth=1, zorder=0)
ax.set_axisbelow(True)
ax.tick_params(axis="both", length=0)

# Small legend clarifying the two states (on-track vs. behind target).
legend_handles = [
    plt.Rectangle((0, 0), 1, 1, color=COLOR_ON_TRACK),
    plt.Rectangle((0, 0), 1, 1, color=COLOR_BEHIND),
]
ax.legend(
    legend_handles,
    ["At/above target", "Materially below target"],
    loc="lower left",
    frameon=False,
    fontsize=9.5,
    labelcolor=COLOR_TEXT_SECONDARY,
)

fig.suptitle(
    "Playbook Review Compliance by Category (SYNTHETIC EXAMPLE DATA)",
    fontsize=14,
    fontweight="bold",
    color=COLOR_TEXT_PRIMARY,
    y=0.98,
)
ax.set_title(
    "% of playbooks reviewed on the scheduled cadence, by category",
    fontsize=10.5,
    color=COLOR_TEXT_SECONDARY,
    pad=12,
)

fig.text(
    0.5,
    0.01,
    "Illustrative synthetic example data for teaching this metric — not measurements from any real SOC.",
    ha="center",
    va="bottom",
    fontsize=8.5,
    color=COLOR_MUTED,
    style="italic",
)

fig.tight_layout(rect=(0, 0.035, 1, 0.94))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/playbook-review-compliance.png"
fig.savefig(output_path, dpi=150, facecolor=COLOR_SURFACE)
print(f"Saved chart to {output_path}")
