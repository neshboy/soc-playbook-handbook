import sys
import os
import subprocess
import tempfile
from PIL import Image, ImageChops

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
MERMAID_JS = os.path.join(TOOLS_DIR, "node_modules", "mermaid", "dist", "mermaid.min.js")

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script src="file:///{mermaid_js}"></script>
<style>
  html, body {{ margin: 0; background: white; overflow: hidden; }}
  .mermaid {{ padding: 28px; display: inline-block; font-family: Segoe UI, Arial, sans-serif; }}
</style>
</head>
<body>
<div class="mermaid">
{diagram}
</div>
<script>
  mermaid.initialize({{
    startOnLoad: true,
    theme: "base",
    themeVariables: {{
      fontSize: "16px",
      background: "#fcfcfb",
      primaryColor: "#9ec5f4",
      primaryTextColor: "#0b0b0b",
      primaryBorderColor: "#2a78d6",
      secondaryColor: "#f9d9c4",
      secondaryTextColor: "#0b0b0b",
      secondaryBorderColor: "#eb6834",
      tertiaryColor: "#bdeedb",
      tertiaryTextColor: "#0b0b0b",
      tertiaryBorderColor: "#1baf7a",
      lineColor: "#52514e",
      textColor: "#0b0b0b",
      mainBkg: "#9ec5f4",
      nodeBorder: "#2a78d6",
      clusterBkg: "#f0efec",
      clusterBorder: "#c3c2b7",
      edgeLabelBackground: "#fcfcfb",
      noteBkgColor: "#fce8bf",
      noteBorderColor: "#eda100",
      noteTextColor: "#0b0b0b",
      actorBkg: "#9ec5f4",
      actorBorder: "#2a78d6",
      actorTextColor: "#0b0b0b",
      signalColor: "#52514e",
      signalTextColor: "#0b0b0b",
      labelBoxBkgColor: "#f9d9c4",
      labelBoxBorderColor: "#eb6834",
      labelTextColor: "#0b0b0b",
      loopTextColor: "#0b0b0b",
      activationBorderColor: "#1baf7a",
      activationBkgColor: "#bdeedb",
    }}
  }});
</script>
</body>
</html>
"""


def find_chrome():
    for path in CHROME_CANDIDATES:
        if os.path.exists(path):
            return path
    raise RuntimeError("No Chrome/Edge executable found in known locations")


def render(mmd_path, out_png_path, window="2200,2200"):
    with open(mmd_path, "r", encoding="utf-8") as f:
        diagram_src = f.read()

    html = HTML_TEMPLATE.format(
        mermaid_js=MERMAID_JS.replace("\\", "/"),
        diagram=diagram_src,
    )

    fd, html_path = tempfile.mkstemp(suffix=".html", dir=TOOLS_DIR)
    os.close(fd)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    fd, raw_png_path = tempfile.mkstemp(suffix=".png", dir=TOOLS_DIR)
    os.close(fd)
    fd, dom_path = tempfile.mkstemp(suffix=".html", dir=TOOLS_DIR)
    os.close(fd)

    chrome = find_chrome()
    file_url = "file:///" + html_path.replace("\\", "/")
    base_cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--hide-scrollbars",
        "--virtual-time-budget=4000",
        "--default-background-color=FFFFFFFF",
    ]
    shot_cmd = base_cmd + [
        "--force-device-scale-factor=2",
        "--screenshot=" + raw_png_path,
        "--window-size=" + window,
        file_url,
    ]
    result = subprocess.run(shot_cmd, capture_output=True, text=True, timeout=60)

    # Second lightweight pass: dump the rendered DOM to detect Mermaid's own
    # "Syntax error in text" error-bomb output, which screenshots successfully
    # but is not a valid diagram.
    dom_cmd = base_cmd + ["--dump-dom", file_url]
    dom_result = subprocess.run(dom_cmd, capture_output=True, text=True, timeout=60)
    dom_html = dom_result.stdout or ""
    if "Syntax error in text" in dom_html:
        for p in (html_path, raw_png_path, dom_path):
            try:
                os.remove(p)
            except OSError:
                pass
        raise RuntimeError(
            "Mermaid reported a syntax error rendering this diagram (error-bomb icon detected). "
            "Fix the .mmd source and retry. Diagram source was:\n" + diagram_src
        )

    try:
        im = Image.open(raw_png_path).convert("RGB")
        bg = Image.new("RGB", im.size, (255, 255, 255))
        diff = ImageChops.difference(im, bg)
        bbox = diff.getbbox()
        if bbox is None:
            raise RuntimeError(
                "Rendered image is blank white - mermaid syntax likely invalid. "
                "Chrome stderr: " + result.stderr[-2000:]
            )
        pad = 16
        l, t, r, b = bbox
        l = max(0, l - pad)
        t = max(0, t - pad)
        r = min(im.width, r + pad)
        b = min(im.height, b + pad)
        if r - l >= im.width - 4 or b - t >= im.height - 4:
            raise RuntimeError(
                "Rendered content fills/exceeds the full capture window - diagram is likely "
                "too large or an error banner is showing. Increase window size or check syntax."
            )
        cropped = im.crop((l, t, r, b))
        os.makedirs(os.path.dirname(out_png_path), exist_ok=True)
        cropped.save(out_png_path)
    finally:
        for p in (html_path, raw_png_path, dom_path):
            try:
                os.remove(p)
            except OSError:
                pass

    print("OK: " + out_png_path + " (" + str(cropped.width) + "x" + str(cropped.height) + ")")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python render_mermaid.py <input.mmd> <output.png> [window WxH]")
        sys.exit(1)
    window = sys.argv[3] if len(sys.argv) > 3 else "2200,2200"
    render(sys.argv[1], sys.argv[2], window)
