import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import {
  STATE_AGENT_PID,
  STATE_CONTROL_PLANE_BASE_URL,
  STATE_STDERR_LOG_PATH,
  STATE_STDOUT_LOG_PATH,
  STATE_SUMMARY_PATH,
  formatError,
  getState,
  log,
  normalizeBaseUrl,
  sleep,
  toPositiveInteger,
} from "./shared.js";

type UploadTokenResponse = {
  readonly upload_token: string;
  readonly expires_at: string;
};

async function runPost(): Promise<void> {
  const controlPlaneBaseUrl = getControlPlaneBaseUrl();

  try {
    await stopAgentIfRunning();
  } catch (error: unknown) {
    log("WARN", `failed while stopping agent: ${formatError(error)}`);
  }

  const summaryPath = getState(STATE_SUMMARY_PATH);
  if (summaryPath === null || summaryPath === "") {
    log("WARN", "no summary path in action state; skipping upload");
    return;
  }

  const summaryBytes = await readSummary(summaryPath);
  if (summaryBytes === null) {
    return;
  }

  await uploadSummary(controlPlaneBaseUrl, summaryBytes);
}

function getControlPlaneBaseUrl(): string {
  const fromState = getState(STATE_CONTROL_PLANE_BASE_URL);
  if (fromState !== null && fromState !== "") {
    return normalizeBaseUrl(fromState);
  }

  return "https://ghapp-control-plane-35h6b4wbbq-uc.a.run.app";
}

async function stopAgentIfRunning(): Promise<void> {
  const pidRaw = getState(STATE_AGENT_PID);
  if (pidRaw === null || pidRaw === "") {
    log("INFO", "no agent PID state found; skip stop step");
    return;
  }

  const pid = toPositiveInteger(pidRaw);
  if (pid === null) {
    log("WARN", `invalid stored PID: ${pidRaw}`);
    return;
  }

  const stdoutLogPath = getState(STATE_STDOUT_LOG_PATH);
  const stderrLogPath = getState(STATE_STDERR_LOG_PATH);

  if (isProcessRunning(pid) === false) {
    log("INFO", `agent process ${pid} already stopped`);
    return;
  }

  log("INFO", `stopping egress agent pid=${pid} with SIGTERM`);
  sendSignal(pid, "SIGTERM");

  const terminatedGracefully = await waitForProcessExit(pid, 15_000);
  if (terminatedGracefully === false) {
    log("WARN", `agent pid=${pid} did not stop after SIGTERM; sending SIGKILL`);
    sendSignal(pid, "SIGKILL");
    const terminatedAfterKill = await waitForProcessExit(pid, 5_000);
    if (terminatedAfterKill === false) {
      log("WARN", `agent pid=${pid} still appears alive after SIGKILL`);
    }
  }

  if (stdoutLogPath !== null && stdoutLogPath !== "") {
    log("INFO", `agent stdout log: ${stdoutLogPath}`);
  }
  if (stderrLogPath !== null && stderrLogPath !== "") {
    log("INFO", `agent stderr log: ${stderrLogPath}`);
  }
}

function sendSignal(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(pid, signal);
  } catch (error: unknown) {
    if (isErrnoWithCode(error) && error.code === "ESRCH") {
      return;
    }
    throw error;
  }
}

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: unknown) {
    if (isErrnoWithCode(error)) {
      if (error.code === "ESRCH") {
        return false;
      }
      if (error.code === "EPERM") {
        return true;
      }
    }
    return false;
  }
}

async function waitForProcessExit(pid: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (isProcessRunning(pid) === false) {
      return true;
    }
    await sleep(250);
  }
  return isProcessRunning(pid) === false;
}

type ErrnoLike = Error & {
  readonly code?: string;
};

function isErrnoWithCode(error: unknown): error is ErrnoLike {
  if (error instanceof Error) {
    const maybeCode = (error as ErrnoLike).code;
    return typeof maybeCode === "string";
  }
  return false;
}

async function readSummary(path: string): Promise<Buffer | null> {
  try {
    const bytes = await readFile(path);
    log("INFO", `loaded summary file (${bytes.byteLength} bytes): ${path}`);
    return bytes;
  } catch (error: unknown) {
    log("WARN", `failed to read summary file ${path}: ${formatError(error)}`);
    return null;
  }
}

async function uploadSummary(controlPlaneBaseUrl: string, summaryBytes: Buffer): Promise<void> {
  const oidcToken = await requestOidcToken(controlPlaneBaseUrl);
  const summarySha256 = createHash("sha256").update(summaryBytes).digest("hex");

  const jobName = readJobName();
  const jobKey = readJobKey(jobName);

  const uploadTokenResponse = await requestUploadToken({
    baseUrl: controlPlaneBaseUrl,
    oidcToken,
    payloadSha256: summarySha256,
    jobName,
    jobKey,
  });

  const runsEndpoint = new URL("/runs", `${controlPlaneBaseUrl}/`).toString();

  const summaryText = summaryBytes.toString("utf8");

  const response = await fetch(runsEndpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${uploadTokenResponse.upload_token}`,
      "Content-Type": "application/json",
    },
    body: summaryText,
  });

  if (!response.ok) {
    const bodyText = await response.text();
    throw new Error(`upload /runs failed with status ${response.status}: ${bodyText}`);
  }

  log("INFO", "uploaded run summary successfully");
}

async function requestOidcToken(audience: string): Promise<string> {
  const requestUrlRaw = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;

  if (requestUrlRaw === undefined || requestUrlRaw === "") {
    throw new Error("ACTIONS_ID_TOKEN_REQUEST_URL is unavailable");
  }
  if (requestToken === undefined || requestToken === "") {
    throw new Error("ACTIONS_ID_TOKEN_REQUEST_TOKEN is unavailable");
  }

  const requestUrl = new URL(requestUrlRaw);
  requestUrl.searchParams.set("audience", audience);

  const response = await fetch(requestUrl, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${requestToken}`,
      "User-Agent": "ghapp-egress-action",
    },
  });

  if (!response.ok) {
    const bodyText = await response.text();
    throw new Error(`OIDC token request failed with status ${response.status}: ${bodyText}`);
  }

  const payload = (await response.json()) as unknown;
  if (isOidcTokenResponse(payload) === false) {
    throw new Error("OIDC response payload is invalid");
  }

  return payload.value;
}

type OidcTokenResponse = {
  readonly value: string;
};

function isOidcTokenResponse(value: unknown): value is OidcTokenResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const record = value as Record<string, unknown>;
  return typeof record.value === "string";
}

async function requestUploadToken(args: {
  readonly baseUrl: string;
  readonly oidcToken: string;
  readonly payloadSha256: string;
  readonly jobName: string;
  readonly jobKey: string;
}): Promise<UploadTokenResponse> {
  const endpoint = new URL("/runs/token", `${args.baseUrl}/`).toString();

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${args.oidcToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      payload_sha256: args.payloadSha256,
      job_name: args.jobName,
      job_key: args.jobKey,
    }),
  });

  if (!response.ok) {
    const bodyText = await response.text();
    throw new Error(`request /runs/token failed with status ${response.status}: ${bodyText}`);
  }

  const payload = (await response.json()) as unknown;
  if (isUploadTokenResponse(payload) === false) {
    throw new Error("upload token response payload is invalid");
  }

  return payload;
}

function isUploadTokenResponse(value: unknown): value is UploadTokenResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const record = value as Record<string, unknown>;
  if (typeof record.upload_token !== "string") {
    return false;
  }
  if (typeof record.expires_at !== "string") {
    return false;
  }

  return true;
}

function readJobName(): string {
  const job = process.env.GITHUB_JOB;
  if (job !== undefined && job !== "") {
    return job;
  }
  return "unknown-job";
}

function readJobKey(jobName: string): string {
  const workflowRef = process.env.GITHUB_WORKFLOW_REF;
  if (workflowRef !== undefined && workflowRef !== "") {
    return `${workflowRef}:${jobName}`;
  }
  return jobName;
}

void runPost().catch((error: unknown) => {
  log("WARN", `post step failed open: ${formatError(error)}`);
});
