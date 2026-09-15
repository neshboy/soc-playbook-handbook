"""
Chart: Repeat Incident Rate by Quarter
Part 28 - Metrics

IMPORTANT: All data in this script is SYNTHETIC EXAMPLE DATA, invented purely to
illustrate the "repeat incident rate" metric concept for the SOC Playbook
Handbook. It is NOT drawn from any real SOC, ticketing system, or incident
log. Do not treat these numbers as benchmarks.
"""

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# SYNTHETIC EXAMPLE DATA (invented for illustration only - not real SOC data)
# "Repeat incidents" = incidents whose root cause matches a prior incident's
# root cause within the same quarter's lookback window.
# ---------------------------------------------------------------------------
quarters = ["Q1", "Q2", "Q3", "Q4"]
repeat_incidents = [17, 12, 8, 5]

fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
fig.patch.set_facecolor("#fcfcfb")
ax.set_facecolor("#fcfcfb")

bar_color = "#2a78d6"  # categorical slot 1 (blue) - single series, no legend needed

bars = ax.bar(
    quarters,
    repeat_incidents,
    color=bar_color,
    width=0.55,
    zorder=3,
)

# Rounded-looking data ends: subtle edge softening via slightly darker top edge
for bar in bars:
    bar.set_edgecolor(bar_color)
    bar.set_linewidth(0)

# Direct value labels on each bar (selective direct labeling - only series)
for bar, value in zip(bars, repeat_incidents):
    ax.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height() + 0.4,
        str(value),
        ha="center",
        va="bottom",
        fontsize=12,
        color="#0b0b0b",
        fontweight="bold",
    )

# Clean style: hide top/right spines, recessive gridlines, muted axis ink
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.spines["left"].set_color("#c3c2b7")
ax.spines["bottom"].set_color("#c3c2b7")

ax.yaxis.grid(True, color="#e1e0d9", linewidth=1, zorder=0)
ax.set_axisbelow(True)
ax.yaxis.set_major_locator(mticker.MultipleLocator(2))

ax.set_ylim(0, max(repeat_incidents) + 4)
ax.set_ylabel("Number of Repeat Incidents\n(same root cause recurring)", fontsize=11, color="#52514e")
ax.set_xlabel("Quarter", fontsize=11, color="#52514e")

ax.tick_params(axis="x", colors="#52514e", labelsize=11)
ax.tick_params(axis="y", colors="#898781", labelsize=10)

# Title includes explicit SYNTHETIC EXAMPLE DATA disclosure
fig.suptitle(
    "Repeat Incident Rate by Quarter",
    fontsize=15,
    fontweight="bold",
    color="#0b0b0b",
    y=0.98,
)
ax.set_title(
    "SYNTHETIC EXAMPLE DATA - illustrative only, not real measurements",
    fontsize=10.5,
    color="#52514e",
    style="italic",
    pad=12,
)

# Footnote reinforcing the synthetic-data disclosure directly on the chart
fig.text(
    0.5,
    0.01,
    "SYNTHETIC EXAMPLE DATA: fabricated figures for teaching purposes only - do not cite as real SOC metrics.",
    ha="center",
    va="bottom",
    fontsize=8.5,
    color="#898781",
)

fig.tight_layout(rect=(0, 0.04, 1, 0.94))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/repeat-incident-rate.png"
fig.savefig(output_path, dpi=150, facecolor=fig.get_facecolor())
print(f"Saved chart to {output_path}")
