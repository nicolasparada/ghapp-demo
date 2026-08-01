import { appendFileSync } from "node:fs";
export const DEFAULT_CONTROL_PLANE_BASE_URL = "https://ghapp-control-plane-35h6b4wbbq-uc.a.run.app";
export const DEFAULT_ACTION_REPOSITORY = "nicolasparada/ghapp-demo";
export const DEFAULT_AGENT_VERSION = "latest";
export const STATE_AGENT_PID = "agent_pid";
export const STATE_SUMMARY_PATH = "summary_path";
export const STATE_READY_PATH = "ready_path";
export const STATE_STDOUT_LOG_PATH = "stdout_log_path";
export const STATE_STDERR_LOG_PATH = "stderr_log_path";
export const STATE_CONTROL_PLANE_BASE_URL = "control_plane_base_url";
export const STATE_EXECUTION_ID = "execution_id";
export const STATE_CAPTURE_STARTED_AT = "capture_started_at";
export function log(level, message) {
    const prefix = `[ghapp-egress-action][${level}]`;
    const line = `${prefix} ${message}`;
    if (level === "INFO") {
        console.log(line);
        return;
    }
    console.error(line);
    if (process.env.GITHUB_ACTIONS === "true") {
        const command = level === "WARN" ? "warning" : "error";
        console.error(`::${command}::${escapeWorkflowCommand(message)}`);
    }
}
function escapeWorkflowCommand(value) {
    return value.replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}
export function saveState(name, value) {
    const githubStateFile = process.env.GITHUB_STATE;
    if (githubStateFile === undefined || githubStateFile === "") {
        process.env[`STATE_${name}`] = value;
        return;
    }
    const escaped = value
        .replaceAll("%", "%25")
        .replaceAll("\r", "%0D")
        .replaceAll("\n", "%0A");
    appendFileSync(githubStateFile, `${name}=${escaped}\n`, { encoding: "utf8" });
}
export function getState(name) {
    const value = process.env[`STATE_${name}`];
    if (value === undefined) {
        return null;
    }
    return value;
}
export function normalizeBaseUrl(raw) {
    const trimmed = raw.trim();
    if (trimmed === "") {
        return DEFAULT_CONTROL_PLANE_BASE_URL;
    }
    if (trimmed.endsWith("/")) {
        return trimmed.slice(0, trimmed.length - 1);
    }
    return trimmed;
}
export function formatError(error) {
    if (error instanceof Error) {
        return `${error.name}: ${error.message}`;
    }
    return String(error);
}
export function sleep(milliseconds) {
    return new Promise((resolve) => {
        setTimeout(resolve, milliseconds);
    });
}
export function readOptionalInputControlPlaneBaseUrl() {
    const input = process.env.INPUT_CONTROL_PLANE_BASE_URL;
    if (input === undefined) {
        return DEFAULT_CONTROL_PLANE_BASE_URL;
    }
    return normalizeBaseUrl(input);
}
export function readActionRepository() {
    const fromRuntime = process.env.GITHUB_ACTION_REPOSITORY;
    if (fromRuntime !== undefined && fromRuntime.trim() !== "") {
        return fromRuntime.trim();
    }
    return DEFAULT_ACTION_REPOSITORY;
}
export function readActionRef() {
    const fromRuntime = process.env.GITHUB_ACTION_REF;
    if (fromRuntime !== undefined && fromRuntime.trim() !== "") {
        return fromRuntime.trim();
    }
    return "latest";
}
export function readOptionalInputAgentVersion() {
    const input = process.env.INPUT_AGENT_VERSION;
    if (input === undefined) {
        return DEFAULT_AGENT_VERSION;
    }
    const trimmed = input.trim();
    if (trimmed === "") {
        return DEFAULT_AGENT_VERSION;
    }
    return trimmed;
}
export function isLinux() {
    return process.platform === "linux";
}
export function toPositiveInteger(value) {
    const parsed = Number.parseInt(value, 10);
    if (Number.isNaN(parsed)) {
        return null;
    }
    if (parsed <= 0) {
        return null;
    }
    return parsed;
}
