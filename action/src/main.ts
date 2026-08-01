import { access, chmod, constants, mkdir, readFile, writeFile } from "node:fs/promises";
import { closeSync, openSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  STATE_AGENT_PID,
  STATE_CONTROL_PLANE_BASE_URL,
  STATE_EXECUTION_ID,
  STATE_CAPTURE_STARTED_AT,
  STATE_READY_PATH,
  STATE_STDERR_LOG_PATH,
  STATE_STDOUT_LOG_PATH,
  STATE_SUMMARY_PATH,
  formatError,
  isLinux,
  log,
  normalizeBaseUrl,
  readActionRef,
  readActionRepository,
  readOptionalInputAgentVersion,
  readOptionalInputControlPlaneBaseUrl,
  saveState,
  sleep,
} from "./shared.js";

const AGENT_CACHE_PREFIX = "ghapp-egress-agent";
const AGENT_READY_TIMEOUT_MS = 20_000;
const AGENT_READY_POLL_INTERVAL_MS = 200;
const AGENT_LOG_TAIL_LINES = 24;

type TargetAsset = {
  readonly targetArch: "amd64" | "arm64";
  readonly archiveName: string;
  readonly binaryName: string;
};

async function runMain(): Promise<void> {
  if (!isLinux()) {
    log("WARN", "runner is not linux; egress agent is linux-only, skipping start");
    return;
  }

  const controlPlaneBaseUrl = normalizeBaseUrl(readOptionalInputControlPlaneBaseUrl());
  const executionId = randomUUID();
  saveState(STATE_EXECUTION_ID, executionId);
  saveState(STATE_CAPTURE_STARTED_AT, new Date().toISOString());
  const actionRepository = readActionRepository();
  const actionRef = readActionRef();
  const agentVersion = readOptionalInputAgentVersion();
  const runnerTemp = resolveRunnerTempDirectory();

  const sessionId = `${Date.now()}-${process.pid}`;
  const sessionDir = join(runnerTemp, AGENT_CACHE_PREFIX, "sessions", sessionId);
  await mkdir(sessionDir, { recursive: true });

  const summaryPath = join(sessionDir, "run-summary.json");
  const readyPath = join(sessionDir, "agent.ready.json");
  const stdoutLogPath = join(sessionDir, "agent.stdout.log");
  const stderrLogPath = join(sessionDir, "agent.stderr.log");

  const targetAsset = resolveTargetAsset(process.arch);
  if (targetAsset === null) {
    log("WARN", `unsupported linux architecture: ${process.arch}; skipping start`);
    return;
  }

  const agentBinaryPath = await ensureAgentBinary({
    actionRepository,
    actionRef,
    agentVersion,
    runnerTemp,
    targetAsset,
  });

  const stdoutFd = openSync(stdoutLogPath, "a");
  const stderrFd = openSync(stderrLogPath, "a");

  try {
    const child = spawn(agentBinaryPath, ["--output", summaryPath, "--ready-file", readyPath], {
      detached: true,
      stdio: ["ignore", stdoutFd, stderrFd],
      env: process.env,
    });

    const pid = child.pid;
    if (pid === undefined) {
      log("WARN", "agent started without PID; skipping post-step integration");
      return;
    }

    child.unref();

    saveState(STATE_AGENT_PID, String(pid));
    saveState(STATE_SUMMARY_PATH, summaryPath);
    saveState(STATE_READY_PATH, readyPath);
    saveState(STATE_STDOUT_LOG_PATH, stdoutLogPath);
    saveState(STATE_STDERR_LOG_PATH, stderrLogPath);
    saveState(STATE_CONTROL_PLANE_BASE_URL, controlPlaneBaseUrl);

    log("INFO", `started egress agent in background (pid=${pid})`);
    log("INFO", `agent version source: ${agentVersion}`);
    log("INFO", `agent summary will be written to ${summaryPath}`);

    await waitForAgentReadiness({
      pid,
      readyPath,
      stdoutLogPath,
      stderrLogPath,
    });
  } finally {
    safeClose(stdoutFd);
    safeClose(stderrFd);
  }
}

function safeClose(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // no-op
  }
}

function resolveRunnerTempDirectory(): string {
  const runnerTemp = process.env.RUNNER_TEMP;
  if (runnerTemp !== undefined && runnerTemp.trim() !== "") {
    return runnerTemp;
  }
  return tmpdir();
}

function resolveTargetAsset(nodeArch: string): TargetAsset | null {
  if (nodeArch === "x64") {
    return {
      targetArch: "amd64",
      archiveName: "egress-agent-linux-amd64.tar.gz",
      binaryName: "egress-agent-linux-amd64",
    };
  }

  if (nodeArch === "arm64") {
    return {
      targetArch: "arm64",
      archiveName: "egress-agent-linux-arm64.tar.gz",
      binaryName: "egress-agent-linux-arm64",
    };
  }

  return null;
}

async function ensureAgentBinary(args: {
  readonly actionRepository: string;
  readonly actionRef: string;
  readonly agentVersion: string;
  readonly runnerTemp: string;
  readonly targetAsset: TargetAsset;
}): Promise<string> {
  const repositoryKey = args.actionRepository.replaceAll("/", "-");
  const refKey = args.actionRef.replaceAll("/", "-").replaceAll(":", "-");
  const versionKey = args.agentVersion.replaceAll("/", "-").replaceAll(":", "-");
  const cacheDir = join(
    args.runnerTemp,
    AGENT_CACHE_PREFIX,
    "bin",
    repositoryKey,
    refKey,
    versionKey,
    args.targetAsset.targetArch,
  );
  const binaryPath = join(cacheDir, args.targetAsset.binaryName);

  if (await fileExists(binaryPath)) {
    return binaryPath;
  }

  await mkdir(cacheDir, { recursive: true });

  const archivePath = join(cacheDir, args.targetAsset.archiveName);
  const downloadUrl = buildReleaseAssetUrl({
    repository: args.actionRepository,
    agentVersion: args.agentVersion,
    assetName: args.targetAsset.archiveName,
  });

  log("INFO", `downloading agent binary: ${downloadUrl}`);
  await downloadFile(downloadUrl, archivePath);

  await extractArchive(archivePath, cacheDir);
  await chmod(binaryPath, 0o755);

  return binaryPath;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function buildReleaseAssetUrl(args: {
  readonly repository: string;
  readonly agentVersion: string;
  readonly assetName: string;
}): string {
  const normalizedVersion = args.agentVersion.trim();
  if (normalizedVersion.toLowerCase() === "latest") {
    return `https://github.com/${args.repository}/releases/latest/download/${args.assetName}`;
  }

  return `https://github.com/${args.repository}/releases/download/${encodeURIComponent(normalizedVersion)}/${args.assetName}`;
}

async function downloadFile(url: string, destinationPath: string): Promise<void> {
  const headers = new Headers();
  headers.set("User-Agent", "ghapp-egress-action");

  const githubToken = process.env.GITHUB_TOKEN;
  if (githubToken !== undefined && githubToken !== "") {
    headers.set("Authorization", `Bearer ${githubToken}`);
  }

  const response = await fetch(url, {
    method: "GET",
    headers,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`download failed with status ${response.status}: ${text}`);
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  await writeFile(destinationPath, bytes);
}

async function extractArchive(archivePath: string, destinationDir: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const tar = spawn("tar", ["-xzf", archivePath, "-C", destinationDir], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderr = "";

    tar.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    tar.on("error", (error: Error) => {
      reject(error);
    });

    tar.on("close", (code: number | null) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(
        new Error(
          `tar extraction failed with code ${String(code)}${stderr !== "" ? `: ${stderr}` : ""}`,
        ),
      );
    });
  });
}

async function waitForAgentReadiness(args: {
  readonly pid: number;
  readonly readyPath: string;
  readonly stdoutLogPath: string;
  readonly stderrLogPath: string;
}): Promise<void> {
  const deadline = Date.now() + AGENT_READY_TIMEOUT_MS;

  while (Date.now() < deadline) {
    if (await fileExists(args.readyPath)) {
      let readinessText = "";
      try {
        readinessText = (await readFile(args.readyPath, { encoding: "utf8" })).trim();
      } catch {
        readinessText = "";
      }

      if (readinessText !== "") {
        log("INFO", `agent readiness confirmed: ${readinessText}`);
      } else {
        log("INFO", `agent readiness confirmed via file: ${args.readyPath}`);
      }
      return;
    }

    const exited = didProcessExit(args.pid);
    if (exited) {
      const stderrTail = await readLogTail(args.stderrLogPath, AGENT_LOG_TAIL_LINES);
      const stdoutTail = await readLogTail(args.stdoutLogPath, AGENT_LOG_TAIL_LINES);
      log(
        "WARN",
        `agent exited before readiness probe succeeded (pid=${args.pid}); egress capture may be unavailable`,
      );
      if (stderrTail !== "") {
        log("WARN", `agent stderr tail:\n${stderrTail}`);
      } else if (stdoutTail !== "") {
        log("WARN", `agent stdout tail:\n${stdoutTail}`);
      }
      return;
    }

    await sleep(AGENT_READY_POLL_INTERVAL_MS);
  }

  const stderrTail = await readLogTail(args.stderrLogPath, AGENT_LOG_TAIL_LINES);
  log(
    "WARN",
    `agent readiness timed out after ${AGENT_READY_TIMEOUT_MS}ms; continuing fail-open`,
  );
  if (stderrTail !== "") {
    log("WARN", `agent stderr tail while waiting readiness:\n${stderrTail}`);
  }
}

function didProcessExit(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error) {
      const maybeCode = (error as Error & { readonly code?: string }).code;
      if (maybeCode === "EPERM") {
        return false;
      }
      if (maybeCode === "ESRCH") {
        return true;
      }
    }
    return false;
  }
}

async function readLogTail(path: string, maxLines: number): Promise<string> {
  try {
    const content = await readFile(path, { encoding: "utf8" });
    const lines = content
      .replaceAll("\r\n", "\n")
      .split("\n")
      .filter((line) => line !== "");

    const tail = lines.slice(-maxLines);
    return tail.join("\n");
  } catch {
    return "";
  }
}

void runMain().catch((error: unknown) => {
  log("WARN", `main step failed open: ${formatError(error)}`);
});
