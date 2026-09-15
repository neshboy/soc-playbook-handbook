const { spawn } = require("child_process");
const fs = require("fs");

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9333;
const HTML_URL = "file:///C:/Users/User/SOC-Playbook-Handbook/_build/book.html";
const OUT_PDF = "C:\\Users\\User\\SOC-Playbook-Handbook\\_build\\SOC_Playbook_Handbook.pdf";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForCdp() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/version`);
      if (res.ok) return;
    } catch (e) {}
    await sleep(500);
  }
  throw new Error("Chrome CDP endpoint never became ready");
}

function cdpSend(ws, id, method, params) {
  return new Promise((resolve, reject) => {
    const onMessage = (event) => {
      const msg = JSON.parse(event.data.toString());
      if (msg.id === id) {
        ws.removeEventListener("message", onMessage);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    };
    ws.addEventListener("message", onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  const chromeProc = spawn(CHROME, [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    `--remote-debugging-port=${PORT}`,
    "--remote-allow-origins=*",
    "about:blank",
  ], { stdio: "ignore" });

  try {
    await waitForCdp();

    const createRes = await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(HTML_URL)}`, { method: "PUT" });
    const target = await createRes.json();
    const wsUrl = target.webSocketDebuggerUrl;

    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener("open", resolve);
      ws.addEventListener("error", reject);
    });

    // Give the page a moment to finish loading (images etc).
    await sleep(4000);

    const footerTemplate = `
      <div style="width:100%; font-size:8px; color:#888; font-family:Arial,sans-serif; padding:0 18mm; display:flex; justify-content:space-between;">
        <span>SIGNAL TO ACTION: The Complete SOC Playbook Handbook</span>
        <span><span class="pageNumber"></span> / <span class="totalPages"></span></span>
      </div>`;

    const result = await cdpSend(ws, 1, "Page.printToPDF", {
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: "<span></span>",
      footerTemplate,
      marginTop: 0.87,
      marginBottom: 0.95,
      marginLeft: 0.71,
      marginRight: 0.71,
      preferCSSPageSize: true,
    });

    fs.writeFileSync(OUT_PDF, Buffer.from(result.data, "base64"));
    console.log("Wrote", OUT_PDF, (fs.statSync(OUT_PDF).size / 1024 / 1024).toFixed(2), "MB");
    ws.close();
  } finally {
    chromeProc.kill();
  }
}

main().catch((err) => {
  console.error("FAILED:", err);
  process.exit(1);
});
