import { access, appendFile, constants, readFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import {
  STATE_AGENT_PID,
  STATE_CONTROL_PLANE_BASE_URL,
  STATE_EXECUTION_ID,
  STATE_CAPTURE_STARTED_AT,
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

const MAX_EMITTED_LOG_LINES = 200;
const RETRYABLE_STATUS_MIN = 500;
const RETRYABLE_STATUS_MAX = 599;
const MAX_UPLOAD_ATTEMPTS = 4;

type UploadTokenResponse = {
  readonly upload_token: string;
  readonly expires_at: string;
};

type AgentLogStream = "stdout" | "stderr";

async function runPost(): Promise<void> {
  const controlPlaneBaseUrl = getControlPlaneBaseUrl();

  try {
    await stopAgentIfRunning();
  } catch (error: unknown) {
    log("WARN", `failed while stopping agent: ${formatError(error)}`);
  }

  await emitAgentLogsFromState();

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
  const summaryPath = getState(STATE_SUMMARY_PATH);

  if (isProcessRunning(pid) === false) {
    log("INFO", `agent process ${pid} already stopped`);
    return;
  }

  log("INFO", `stopping egress agent pid=${pid} with SIGTERM`);
  sendSignal(pid, "SIGTERM");

  const gracefulResult = await waitForProcessExitOrSummary(pid, summaryPath, 20_000);

  if (gracefulResult.processExited === false) {
    if (gracefulResult.summaryFileReady) {
      log(
        "INFO",
        `summary file appeared before process exit; skipping SIGKILL to avoid truncating output (pid=${pid})`,
      );
    } else {
      log("WARN", `agent pid=${pid} did not stop after SIGTERM; sending SIGKILL`);
      sendSignal(pid, "SIGKILL");
      const terminatedAfterKill = await waitForProcessExit(pid, 5_000);
      if (terminatedAfterKill === false) {
        log("WARN", `agent pid=${pid} still appears alive after SIGKILL`);
      }
    }
  }

  if (stdoutLogPath !== null && stdoutLogPath !== "") {
    log("INFO", `agent stdout log: ${stdoutLogPath}`);
  }
  if (stderrLogPath !== null && stderrLogPath !== "") {
    log("INFO", `agent stderr log: ${stderrLogPath}`);
  }
}

async function emitAgentLogsFromState(): Promise<void> {
  const stdoutLogPath = getState(STATE_STDOUT_LOG_PATH);
  const stderrLogPath = getState(STATE_STDERR_LOG_PATH);

  await emitAgentLog(stdoutLogPath, "stdout");
  await emitAgentLog(stderrLogPath, "stderr");
}

async function emitAgentLog(path: string | null, stream: AgentLogStream): Promise<void> {
  if (path === null || path === "") {
    log("INFO", `no ${stream} log path in state`);
    return;
  }

  try {
    const content = await readFile(path, { encoding: "utf8" });
    const allLines = splitLines(content);
    const tailLines = allLines.slice(-MAX_EMITTED_LOG_LINES);
    const omittedLineCount = allLines.length - tailLines.length;

    log(
      "INFO",
      `emitting agent ${stream} log tail (${tailLines.length}/${allLines.length} lines) from ${path}`,
    );

    for (const line of tailLines) {
      if (stream === "stdout") {
        console.log(`[ghapp-egress-agent:${stream}] ${line}`);
      } else {
        console.error(`[ghapp-egress-agent:${stream}] ${line}`);
      }
    }

    await appendStepSummary(renderLogSummaryBlock({
      stream,
      path,
      omittedLineCount,
      totalLineCount: allLines.length,
      tailLines,
    }));
  } catch (error: unknown) {
    log("WARN", `failed reading agent ${stream} log ${path}: ${formatError(error)}`);
  }
}

function splitLines(content: string): ReadonlyArray<string> {
  const normalized = content.replaceAll("\r\n", "\n");
  const rawLines = normalized.split("\n");

  const lines: string[] = [];
  for (const rawLine of rawLines) {
    if (rawLine !== "") {
      lines.push(rawLine);
    }
  }

  return lines;
}

function renderLogSummaryBlock(args: {
  readonly stream: AgentLogStream;
  readonly path: string;
  readonly omittedLineCount: number;
  readonly totalLineCount: number;
  readonly tailLines: ReadonlyArray<string>;
}): string {
  const title = `### Agent ${args.stream} log`;
  const metadata =
    `Path: \`${args.path}\`  \n` +
    `Lines shown: ${args.tailLines.length}/${args.totalLineCount}` +
    (args.omittedLineCount > 0 ? ` (omitted ${args.omittedLineCount})` : "");

  const fenced = ["```text", ...args.tailLines, "```"].join("\n");
  return `${title}\n\n${metadata}\n\n${fenced}\n\n`;
}

async function appendStepSummary(markdown: string): Promise<void> {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath === undefined || summaryPath === "") {
    return;
  }

  try {
    await appendFile(summaryPath, markdown, { encoding: "utf8" });
  } catch (error: unknown) {
    log("WARN", `failed writing step summary: ${formatError(error)}`);
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

async function waitForProcessExitOrSummary(
  pid: number,
  summaryPath: string | null,
  timeoutMs: number,
): Promise<{ processExited: boolean; summaryFileReady: boolean }> {
  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    const processExited = isProcessRunning(pid) === false;
    const summaryFileReady = await fileExists(summaryPath);

    if (processExited || summaryFileReady) {
      return { processExited, summaryFileReady };
    }

    await sleep(250);
  }

  return {
    processExited: isProcessRunning(pid) === false,
    summaryFileReady: await fileExists(summaryPath),
  };
}

async function fileExists(path: string | null): Promise<boolean> {
  if (path === null || path === "") {
    return false;
  }

  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
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
		executionId: readExecutionID(),
		jobName,
		jobKey,
		runnerName: readRunnerName(),
		runnerOS: readRunnerOS(),
		captureStartedAt: readCaptureStartedAt(),
		captureEndedAt: new Date().toISOString(),
	});

  const runsEndpoint = new URL("/runs", `${controlPlaneBaseUrl}/`).toString();

  const summaryText = summaryBytes.toString("utf8");

  const response = await fetchWithRetry(runsEndpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${uploadTokenResponse.upload_token}`,
      "Content-Type": "application/json",
    },
    body: summaryText,
  }, "upload /runs");

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

  const response = await fetchWithRetry(requestUrl, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${requestToken}`,
      "User-Agent": "ghapp-egress-action",
    },
  }, "request OIDC token");

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

async function fetchWithRetry(input: URL | string, init: RequestInit, label: string): Promise<Response> {
  let lastError: unknown = null;

  for (let attempt = 1; attempt <= MAX_UPLOAD_ATTEMPTS; attempt++) {
    try {
      const response = await fetch(input, init);
      if (
        response.status >= RETRYABLE_STATUS_MIN &&
        response.status <= RETRYABLE_STATUS_MAX &&
        attempt < MAX_UPLOAD_ATTEMPTS
      ) {
        log("WARN", `${label} returned ${response.status}; retrying attempt ${attempt + 1}/${MAX_UPLOAD_ATTEMPTS}`);
        await response.arrayBuffer();
        await sleep(backoffDelayMs(attempt));
        continue;
      }
      return response;
    } catch (error: unknown) {
      lastError = error;
      if (attempt >= MAX_UPLOAD_ATTEMPTS) {
        break;
      }
      log(
        "WARN",
        `${label} failed on attempt ${attempt}/${MAX_UPLOAD_ATTEMPTS}: ${formatError(error)}; retrying`,
      );
      await sleep(backoffDelayMs(attempt));
    }
  }

  throw new Error(`${label} failed after ${MAX_UPLOAD_ATTEMPTS} attempts: ${formatError(lastError)}`);
}

function backoffDelayMs(attempt: number): number {
  const base = 300;
  const delay = base * 2 ** (attempt - 1);
  return Math.min(delay, 3000);
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
	readonly executionId: string;
	readonly jobName: string;
	readonly jobKey: string;
	readonly runnerName: string;
	readonly runnerOS: string;
	readonly captureStartedAt: string;
	readonly captureEndedAt: string;
}): Promise<UploadTokenResponse> {
  const endpoint = new URL("/runs/token", `${args.baseUrl}/`).toString();

  const response = await fetchWithRetry(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${args.oidcToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      payload_sha256: args.payloadSha256,
      execution_id: args.executionId,
      job_name: args.jobName,
      job_key: args.jobKey,
      runner_name: args.runnerName,
      runner_os: args.runnerOS,
      capture_started_at: args.captureStartedAt,
      capture_ended_at: args.captureEndedAt,
    }),
  }, "request /runs/token");

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

function readExecutionID(): string {
  const fromState = getState(STATE_EXECUTION_ID);
  if (fromState !== null && fromState !== "") {
    return fromState;
  }
  return randomUUID();
}

function readCaptureStartedAt(): string {
  const fromState = getState(STATE_CAPTURE_STARTED_AT);
  if (fromState !== null && fromState !== "") {
    return fromState;
  }
  return new Date().toISOString();
}

function readRunnerName(): string {
  return process.env.RUNNER_NAME ?? "";
}

function readRunnerOS(): string {
  return process.env.RUNNER_OS ?? "";
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
