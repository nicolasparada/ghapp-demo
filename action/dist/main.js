import { access, chmod, constants, mkdir, writeFile } from "node:fs/promises";
import { closeSync, openSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { STATE_AGENT_PID, STATE_CONTROL_PLANE_BASE_URL, STATE_STDERR_LOG_PATH, STATE_STDOUT_LOG_PATH, STATE_SUMMARY_PATH, formatError, isLinux, log, normalizeBaseUrl, readActionRef, readActionRepository, readOptionalInputAgentVersion, readOptionalInputControlPlaneBaseUrl, saveState, } from "./shared.js";
const AGENT_CACHE_PREFIX = "ghapp-egress-agent";
async function runMain() {
    if (!isLinux()) {
        log("WARN", "runner is not linux; egress agent is linux-only, skipping start");
        return;
    }
    const controlPlaneBaseUrl = normalizeBaseUrl(readOptionalInputControlPlaneBaseUrl());
    const actionRepository = readActionRepository();
    const actionRef = readActionRef();
    const agentVersion = readOptionalInputAgentVersion();
    const runnerTemp = resolveRunnerTempDirectory();
    const sessionId = `${Date.now()}-${process.pid}`;
    const sessionDir = join(runnerTemp, AGENT_CACHE_PREFIX, "sessions", sessionId);
    await mkdir(sessionDir, { recursive: true });
    const summaryPath = join(sessionDir, "run-summary.json");
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
        const child = spawn(agentBinaryPath, ["--output", summaryPath], {
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
        saveState(STATE_STDOUT_LOG_PATH, stdoutLogPath);
        saveState(STATE_STDERR_LOG_PATH, stderrLogPath);
        saveState(STATE_CONTROL_PLANE_BASE_URL, controlPlaneBaseUrl);
        log("INFO", `started egress agent in background (pid=${pid})`);
        log("INFO", `agent version source: ${agentVersion}`);
        log("INFO", `agent summary will be written to ${summaryPath}`);
    }
    finally {
        safeClose(stdoutFd);
        safeClose(stderrFd);
    }
}
function safeClose(fd) {
    try {
        closeSync(fd);
    }
    catch {
        // no-op
    }
}
function resolveRunnerTempDirectory() {
    const runnerTemp = process.env.RUNNER_TEMP;
    if (runnerTemp !== undefined && runnerTemp.trim() !== "") {
        return runnerTemp;
    }
    return tmpdir();
}
function resolveTargetAsset(nodeArch) {
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
async function ensureAgentBinary(args) {
    const repositoryKey = args.actionRepository.replaceAll("/", "-");
    const refKey = args.actionRef.replaceAll("/", "-").replaceAll(":", "-");
    const versionKey = args.agentVersion.replaceAll("/", "-").replaceAll(":", "-");
    const cacheDir = join(args.runnerTemp, AGENT_CACHE_PREFIX, "bin", repositoryKey, refKey, versionKey, args.targetAsset.targetArch);
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
async function fileExists(path) {
    try {
        await access(path, constants.F_OK);
        return true;
    }
    catch {
        return false;
    }
}
function buildReleaseAssetUrl(args) {
    const normalizedVersion = args.agentVersion.trim();
    if (normalizedVersion.toLowerCase() === "latest") {
        return `https://github.com/${args.repository}/releases/latest/download/${args.assetName}`;
    }
    return `https://github.com/${args.repository}/releases/download/${encodeURIComponent(normalizedVersion)}/${args.assetName}`;
}
async function downloadFile(url, destinationPath) {
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
async function extractArchive(archivePath, destinationDir) {
    await new Promise((resolve, reject) => {
        const tar = spawn("tar", ["-xzf", archivePath, "-C", destinationDir], {
            stdio: ["ignore", "pipe", "pipe"],
        });
        let stderr = "";
        tar.stderr.on("data", (chunk) => {
            stderr += chunk.toString("utf8");
        });
        tar.on("error", (error) => {
            reject(error);
        });
        tar.on("close", (code) => {
            if (code === 0) {
                resolve();
                return;
            }
            reject(new Error(`tar extraction failed with code ${String(code)}${stderr !== "" ? `: ${stderr}` : ""}`));
        });
    });
}
void runMain().catch((error) => {
    log("WARN", `main step failed open: ${formatError(error)}`);
});
