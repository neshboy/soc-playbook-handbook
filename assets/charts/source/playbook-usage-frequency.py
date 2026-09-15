"""
Most Frequently Invoked Playbooks -- SOC Playbook Handbook, Part 28 (Metrics)

IMPORTANT: All data in this script is SYNTHETIC EXAMPLE DATA, invented purely
to illustrate the "playbook invocation frequency" metric concept. It is NOT
pulled from any real SOC, SOAR platform, or ticketing system. Do not treat
these counts as benchmarks.
"""

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

# ---------------------------------------------------------------------------
# SYNTHETIC data: playbook name -> invented invocation count over one month.
# Names are real playbook titles used elsewhere in this handbook; counts are
# made up for teaching purposes only.
# ---------------------------------------------------------------------------
playbook_names = [
    "Phishing",
    "Encoded PowerShell",
    "Impossible Travel",
    "Password Spraying",
    "Malicious OAuth Grant",
    "Suspicious Login (MFA Bypass)",
    "Ransomware Precursor",
    "DNS Tunneling",
    "Insider Data Exfiltration",
    "Business Email Compromise",
]

invocation_counts = [
    412,
    287,
    239,
    198,
    164,
    141,
    118,
    96,
    77,
    58,
]

# Sort descending by count (largest bar on top), top 10 already curated above.
paired = sorted(zip(playbook_names, invocation_counts), key=lambda p: p[1])
sorted_names = [p[0] for p in paired]
sorted_counts = [p[1] for p in paired]

# ---------------------------------------------------------------------------
# Palette (dataviz skill reference instance, light mode, single-series job)
# ---------------------------------------------------------------------------
COLOR_BAR = "#2a78d6"        # categorical slot 1 / sequential hue, blue
COLOR_SURFACE = "#fcfcfb"
COLOR_PRIMARY_INK = "#0b0b0b"
COLOR_SECONDARY_INK = "#52514e"
COLOR_MUTED = "#898781"
COLOR_GRID = "#e1e0d9"
COLOR_BASELINE = "#c3c2b7"

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = [
    "Segoe UI", "DejaVu Sans", "Arial", "sans-serif"
]

fig, ax = plt.subplots(figsize=(10, 6.5), dpi=150)
fig.patch.set_facecolor(COLOR_SURFACE)
ax.set_facecolor(COLOR_SURFACE)

y_pos = range(len(sorted_names))
bar_height = 0.6  # thin mark, leaves air in the slot

bars = ax.barh(
    y_pos,
    sorted_counts,
    height=bar_height,
    color=COLOR_BAR,
    edgecolor="none",
    zorder=3,
)

# Direct labels: value at the tip of every bar (sparing, single series -> ok)
max_count = max(sorted_counts)
for bar, count in zip(bars, sorted_counts):
    ax.text(
        bar.get_width() + max_count * 0.015,
        bar.get_y() + bar.get_height() / 2,
        f"{count:,}",
        va="center",
        ha="left",
        fontsize=10.5,
        color=COLOR_SECONDARY_INK,
        zorder=4,
    )

# Axis / ticks
ax.set_yticks(list(y_pos))
ax.set_yticklabels(sorted_names, fontsize=11, color=COLOR_PRIMARY_INK)
ax.set_xlabel(
    "Playbook invocations over 30 days (synthetic)",
    fontsize=10.5,
    color=COLOR_MUTED,
    labelpad=10,
)

ax.set_xlim(0, max_count * 1.16)
ax.tick_params(axis="x", colors=COLOR_MUTED, labelsize=10)
ax.tick_params(axis="y", length=0)

# Recessive gridlines behind the bars, hairline, solid, vertical only
ax.xaxis.grid(True, color=COLOR_GRID, linewidth=1, zorder=0)
ax.yaxis.grid(False)
ax.set_axisbelow(True)

# Baseline (x=0) drawn slightly heavier than gridlines
ax.axvline(0, color=COLOR_BASELINE, linewidth=1.2, zorder=2)

# Hide top/right/left spines; keep a faint bottom spine
for spine_name in ("top", "right", "left"):
    ax.spines[spine_name].set_visible(False)
ax.spines["bottom"].set_color(COLOR_BASELINE)
ax.spines["bottom"].set_linewidth(1)

# Title + synthetic-data disclosure (must be visible on the chart itself)
fig.suptitle(
    "Most Frequently Invoked Playbooks",
    fontsize=16,
    fontweight="bold",
    color=COLOR_PRIMARY_INK,
    x=0.02,
    ha="left",
    y=0.985,
)
ax.set_title(
    "SYNTHETIC EXAMPLE DATA -- illustrative counts, not measurements from a real SOC",
    fontsize=11,
    color=COLOR_SECONDARY_INK,
    loc="left",
    style="italic",
    pad=14,
)

# Footnote reinforcing the disclosure at the bottom of the figure
fig.text(
    0.02,
    0.01,
    "Note: Playbook names are real examples from this handbook; invocation counts "
    "are fabricated for teaching purposes only and do not reflect any actual SOC.",
    fontsize=8.5,
    color=COLOR_MUTED,
    ha="left",
    va="bottom",
)

fig.tight_layout(rect=(0, 0.035, 1, 0.93))

output_path = "C:/Users/User/SOC-Playbook-Handbook/assets/charts/playbook-usage-frequency.png"
fig.savefig(output_path, dpi=150, facecolor=COLOR_SURFACE)
print(f"Saved chart to {output_path}")
