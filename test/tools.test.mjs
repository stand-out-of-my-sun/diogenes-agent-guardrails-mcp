import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const manifestPath = path.resolve(__dirname, "../tools_manifest.json");
const tools = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const toolMap = new Map(tools.map(t => [t.name, t]));

test("Manifest Integrity: agent-guardrails declares exactly 12 tools", () => {
  assert.equal(tools.length, 12, "Tool count must match manifest");
});

test("Audit tool schema & hints: verify_agent_command_safety", () => {
  const tool = toolMap.get("verify_agent_command_safety");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: validate_sql_query_ast", () => {
  const tool = toolMap.get("validate_sql_query_ast");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: execute_python_sandbox", () => {
  const tool = toolMap.get("execute_python_sandbox");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: audit_mcp_server_manifest", () => {
  const tool = toolMap.get("audit_mcp_server_manifest");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: detect_mcp_schema_rugpull", () => {
  const tool = toolMap.get("detect_mcp_schema_rugpull");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: validate_mcp_sampling_request", () => {
  const tool = toolMap.get("validate_mcp_sampling_request");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: sanitize_tool_output_stream", () => {
  const tool = toolMap.get("sanitize_tool_output_stream");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: redact_sensitive_pii", () => {
  const tool = toolMap.get("redact_sensitive_pii");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: detect_agent_action_loop", () => {
  const tool = toolMap.get("detect_agent_action_loop");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: verify_a2a_agent_card", () => {
  const tool = toolMap.get("verify_a2a_agent_card");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: audit_outbound_egress_url", () => {
  const tool = toolMap.get("audit_outbound_egress_url");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

test("Audit tool schema & hints: audit_response_factuality", () => {
  const tool = toolMap.get("audit_response_factuality");
  assert.ok(tool, "Tool must exist");
  assert.equal(typeof tool.name, "string");
  assert.ok(tool.description && tool.description.length > 20);
  assert.equal(typeof tool.inputSchema, "object");
  assert.equal(tool.inputSchema.type, "object");
  assert.ok(tool.annotations);
  assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
  assert.equal(typeof tool.annotations.destructiveHint, "boolean");
  assert.equal(typeof tool.annotations.idempotentHint, "boolean");
  assert.equal(typeof tool.annotations.openWorldHint, "boolean");
});

