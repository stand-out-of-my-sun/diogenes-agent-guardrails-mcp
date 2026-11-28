#!/usr/bin/env node
/**
 * Diogenes Agent Guardrails & Command Sandbox MCP
 * Zero-dependency stdio MCP bridge with instant local tools/list resolution
 * and L402 / HTTP 402 micro-payment challenge interception.
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const childProcess = require("child_process");

const DEFAULT_GATEWAY_URL = "https://diogenesgateway.com/mcp/agent-guardrails";
const GATEWAY_URL = process.env.DIOGENES_GATEWAY_URL || DEFAULT_GATEWAY_URL;

// Load local tools manifest for instantaneous zero-latency discovery
let toolsList = [];
try {
  const manifestPath = path.join(__dirname, "tools_manifest.json");
  if (fs.existsSync(manifestPath)) {
    toolsList = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  }
} catch (e) {
  toolsList = [];
}

/**
 * Executes an MCP request with upstream edge gateway forwarding,
 * handling HTTP 402 Payment Required challenges transparently.
 */
async function executeWithPayment(req) {
  const isDemo = process.env.DIOGENES_DEMO === "true" || process.env.DIOGENES_DEMO === "1";
  let targetUrl = GATEWAY_URL;
  if (isDemo && !targetUrl.includes("demo=true")) {
    targetUrl += (targetUrl.includes("?") ? "&" : "?") + "demo=true";
  }

  const baseHeaders = {
    "Content-Type": "application/json",
    "User-Agent": "Diogenes-MCP-Node-Bridge/1.4.0 (Stdio-Autopay)"
  };

  if (isDemo) {
    baseHeaders["X-Demo"] = "true";
  }
  if (process.env.DIOGENES_L402_TOKEN) {
    const tok = process.env.DIOGENES_L402_TOKEN.trim();
    baseHeaders["Authorization"] = tok.startsWith("L402 ") ? tok : `L402 ${tok}`;
  }
  if (process.env.DIOGENES_WALLET_KEY) {
    baseHeaders["X-Wallet-Key"] = process.env.DIOGENES_WALLET_KEY.trim();
  }
  if (process.env.DIOGENES_X402_SIGNATURE) {
    baseHeaders["X-Payment-Signature"] = process.env.DIOGENES_X402_SIGNATURE.trim();
  }
  if (process.env.DIOGENES_GRLC_TXHASH) {
    baseHeaders["X-Garlicoin-TxHash"] = process.env.DIOGENES_GRLC_TXHASH.trim();
  }
  if (process.env.DIOGENES_GRLC_PAYER_ADDRESS) {
    baseHeaders["X-Garlicoin-Payer-Address"] = process.env.DIOGENES_GRLC_PAYER_ADDRESS.trim();
  }
  const sessionKey = process.env.DIOGENES_SESSION_KEY || process.env.DIOGENES_GRLC_SESSION_KEY || process.env.DIOGENES_API_KEY;
  if (sessionKey && !baseHeaders["Authorization"]) {
    const sk = sessionKey.trim();
    baseHeaders["Authorization"] = sk.toLowerCase().startsWith("bearer ") ? sk : `Bearer ${sk}`;
  }
  if (process.env.DIOGENES_BASE_TXHASH) {
    baseHeaders["X-Payment-TxHash"] = process.env.DIOGENES_BASE_TXHASH.trim();
  }
  if (process.env.DIOGENES_WGRLC_TXHASH || process.env.DIOGENES_BSC_TXHASH) {
    baseHeaders["X-BSC-TxHash"] = (process.env.DIOGENES_WGRLC_TXHASH || process.env.DIOGENES_BSC_TXHASH).trim();
  }
  if (process.env.DIOGENES_GRLC_TXID && !baseHeaders["X-Garlicoin-TxHash"]) {
    baseHeaders["X-Garlicoin-TxHash"] = process.env.DIOGENES_GRLC_TXID.trim();
  }

  async function sendReq(url, headers, bodyObj) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);
    try {
      return await fetch(url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(bodyObj),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  let res;
  try {
    res = await sendReq(targetUrl, baseHeaders, req);
  } catch (err) {
    return {
      jsonrpc: "2.0",
      id: req.id,
      error: {
        code: -32603,
        message: "Upstream edge gateway connection error: " + err.message
      }
    };
  }

  // Intercept HTTP 402 Payment Required
  if (res.status === 402) {
    const wwwAuth = res.headers.get("www-authenticate") || "";
    let bodyJson = null;
    try {
      const bodyText = await res.text();
      bodyJson = JSON.parse(bodyText);
    } catch (e) {
      bodyJson = null;
    }

    let invoice = bodyJson?.invoice || "";
    let macaroon = bodyJson?.macaroon || "";
    const priceSats = bodyJson?.price_sats || bodyJson?.amount_sats || 0;

    if (!invoice && wwwAuth) {
      const invMatch = wwwAuth.match(/invoice="([^"]+)"/) || wwwAuth.match(/invoice=([^\s,]+)/);
      if (invMatch) invoice = invMatch[1];
    }
    if (!macaroon && wwwAuth) {
      const macMatch = wwwAuth.match(/macaroon="([^"]+)"/) || wwwAuth.match(/macaroon=([^\s,]+)/);
      if (macMatch) macaroon = macMatch[1];
    }

    let paidPreimage = null;

    // 1. Auto-settle via Coinos API
    if (process.env.DIOGENES_COINOS_TOKEN && invoice) {
      try {
        const coinosRes = await fetch("https://coinos.io/api/lightning/send", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${process.env.DIOGENES_COINOS_TOKEN.trim()}`
          },
          body: JSON.stringify({ invoice: invoice })
        });
        if (coinosRes.ok) {
          const coinosData = await coinosRes.json();
          paidPreimage = coinosData.preimage || coinosData.payment_preimage || coinosData.hash || null;
        }
      } catch (e) {
        // Coinos auto-pay skipped on error
      }
    }

    // 2. Auto-settle via local CLI command (Strict BOLT11 Bech32 validation prevents shell injection)
    const SAFE_BOLT11_REGEX = /^(?:lightning:)?ln(?:bc|tb|bcrt|sb)[0-9a-z]{20,2048}$/i;
    if (!paidPreimage && process.env.DIOGENES_LN_PAY_CMD && invoice && SAFE_BOLT11_REGEX.test(invoice.trim())) {
      try {
        const safeInvoice = invoice.trim().replace(/^lightning:/i, "");
        const cmd = process.env.DIOGENES_LN_PAY_CMD.replace(/%INVOICE%/g, safeInvoice);
        const stdout = childProcess.execSync(cmd, { encoding: "utf-8", timeout: 15000 });
        const match = stdout.match(/\b([a-f0-9]{64})\b/i);
        if (match) {
          paidPreimage = match[1];
        }
      } catch (e) {
        // CLI auto-pay skipped on error
      }
    }

    // If auto-settled, retry upstream request with L402 credentials
    if (paidPreimage) {
      const retryHeaders = {
        ...baseHeaders,
        "Authorization": `L402 ${macaroon ? macaroon + ":" : ""}${paidPreimage}`
      };
      try {
        const retryRes = await sendReq(targetUrl, retryHeaders, req);
        if (retryRes.ok) {
          return await retryRes.json();
        }
      } catch (e) {
        // Retry failed, proceed to markdown guidance
      }
    }

    // Informative MCP response without crashing stdio client session
    const noticeText = [
      "⚡ **HTTP 402 Payment Required: L402 Microservice Paywall**",
      "",
      `This endpoint requires a micro-payment of **${priceSats ? priceSats + " sats" : "satoshis"}** to execute.`,
      "",
      "### ⚡ Lightning Invoice (BOLT11)",
      "```",
      invoice || "Invoice unavailable",
      "```",
      "",
      "### 🚀 Seamless Options:",
      "1. **Free Demo Mode**: Add `\"env\": { \"DIOGENES_DEMO\": \"true\" }` to your MCP client config for sandbox previews.",
      "2. **Auto-Pay via Coinos**: Add `\"env\": { \"DIOGENES_COINOS_TOKEN\": \"<token>\" }` to auto-settle L402 challenges behind the scenes.",
      "3. **Local CLI Auto-Pay**: Add `\"env\": { \"DIOGENES_LN_PAY_CMD\": \"alby pay %INVOICE%\" }`.",
      "4. **Direct L402 Token**: Add `\"env\": { \"DIOGENES_L402_TOKEN\": \"<macaroon>:<preimage>\" }`."
    ].join("\n");

    return {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        isError: true,
        content: [
          {
            type: "text",
            text: noticeText
          }
        ]
      }
    };
  }

  const rawBodyText = await res.text();
  let parsedRpc = null;
  try {
    parsedRpc = JSON.parse(rawBodyText);
  } catch (e) {
    return {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        content: [{ type: "text", text: rawBodyText }]
      }
    };
  }

  // Intercept MCP JSON-RPC 200 in-band 402 Payment Challenge for zero-click auto-settlement
  const inBandChallenge = parsedRpc?.result?.payment_challenge ||
    (parsedRpc?.result?.error_code === 402 ? parsedRpc.result : null);
  const l402Option = inBandChallenge?.rail_options?.lightning_l402;
  if (l402Option && (process.env.DIOGENES_COINOS_TOKEN || process.env.DIOGENES_LN_PAY_CMD)) {
    const invoice = l402Option.bolt11_invoice || "";
    const macaroon = l402Option.macaroon || "";
    let paidPreimage = null;

    if (process.env.DIOGENES_COINOS_TOKEN && invoice) {
      try {
        const coinosRes = await fetch("https://coinos.io/api/lightning/send", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${process.env.DIOGENES_COINOS_TOKEN.trim()}`
          },
          body: JSON.stringify({ invoice: invoice })
        });
        if (coinosRes.ok) {
          const coinosData = await coinosRes.json();
          paidPreimage = coinosData.preimage || coinosData.payment_preimage || coinosData.hash || null;
        }
      } catch (e) {}
    }

    const SAFE_BOLT11_REGEX = /^(?:lightning:)?ln(?:bc|tb|bcrt|sb)[0-9a-z]{20,2048}$/i;
    if (!paidPreimage && process.env.DIOGENES_LN_PAY_CMD && invoice && SAFE_BOLT11_REGEX.test(invoice.trim())) {
      try {
        const safeInvoice = invoice.trim().replace(/^lightning:/i, "");
        const cmd = process.env.DIOGENES_LN_PAY_CMD.replace(/%INVOICE%/g, safeInvoice);
        const stdout = childProcess.execSync(cmd, { encoding: "utf-8", timeout: 15000 });
        const match = stdout.match(/\b([a-f0-9]{64})\b/i);
        if (match) paidPreimage = match[1];
      } catch (e) {}
    }

    if (paidPreimage) {
      const retryHeaders = {
        ...baseHeaders,
        "Authorization": `L402 ${macaroon ? macaroon + ":" : ""}${paidPreimage}`
      };
      const retryReq = JSON.parse(JSON.stringify(req));
      if (retryReq.params && typeof retryReq.params === "object") {
        retryReq.params.arguments = {
          ...(retryReq.params.arguments || {}),
          payment_proof: paidPreimage
        };
      }
      try {
        const retryRes = await sendReq(targetUrl, retryHeaders, retryReq);
        if (retryRes.ok) {
          return await retryRes.json();
        }
      } catch (e) {}
    }
  }

  return parsedRpc;
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on("line", async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let req;
  try {
    req = JSON.parse(trimmed);
  } catch (e) {
    return;
  }

  // MCP notifications do not expect a response
  if (req.method && req.method.startsWith("notifications/")) {
    return;
  }

  // 1. Instant local response for initialize
  if (req.method === "initialize") {
    const initResp = {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        protocolVersion: req.params?.protocolVersion || "2024-11-05",
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        serverInfo: {
          name: "diogenes-agent-guardrails-mcp",
          version: "1.4.0"
        }
      }
    };
    process.stdout.write(JSON.stringify(initResp) + "\n");
    return;
  }

  // 1b. Instant local response for ping, resources/list, and prompts/list
  if (req.method === "ping") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: {} }) + "\n");
    return;
  }
  if (req.method === "resources/list") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { resources: [] } }) + "\n");
    return;
  }
  if (req.method === "resources/templates/list") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { resourceTemplates: [] } }) + "\n");
    return;
  }
  if (req.method === "prompts/list") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { prompts: [] } }) + "\n");
    return;
  }

  // 2. Instant local response for tools/list
  if (req.method === "tools/list" && toolsList.length > 0) {
    const toolsResp = {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        tools: toolsList
      }
    };
    process.stdout.write(JSON.stringify(toolsResp) + "\n");
    return;
  }

  // 3. Forward execution (tools/call and others) with auto-payment handling
  try {
    const result = await executeWithPayment(req);
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (err) {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: req.id !== undefined ? req.id : null,
      error: { code: -32603, message: "Internal stdio bridge error: " + (err && err.message ? err.message : String(err)) }
    }) + "\n");
  }
});
