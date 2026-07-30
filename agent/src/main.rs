#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("[ERROR] egress-agent is linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::entrypoint();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::env;
    use std::fmt::Write as _;
    use std::fs::{self, File};
    use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const DEFAULT_MAX_EVENTS: usize = 200_000;
    const MAX_LINEAGE_DEPTH: usize = 64;

    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

    const SIGINT: i32 = 2;
    const SIGQUIT: i32 = 3;
    const SIGTERM: i32 = 15;
    const SIGHUP: i32 = 1;
    const SIG_ERR: usize = usize::MAX;

    unsafe extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }

    extern "C" fn handle_termination_signal(_: i32) {
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }

    fn install_signal_handlers() -> Result<(), String> {
        for signum in [SIGINT, SIGQUIT, SIGTERM, SIGHUP] {
            // SAFETY: binding a simple signal handler for process lifetime; handler only sets
            // an AtomicBool, which is async-signal-safe for this constrained usage.
            let previous = unsafe { signal(signum, handle_termination_signal) };
            if previous == SIG_ERR {
                return Err(format!(
                    "failed to install signal handler for signal {signum}"
                ));
            }
        }
        Ok(())
    }

    fn shutdown_requested() -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
    }

    const BPFTRACE_SCRIPT_CONNECT_V4V6: &str = r#"
tracepoint:syscalls:sys_enter_connect
/args->addrlen >= 16/
{
  $family = *(uint16*)args->uservaddr;
  if ($family == 2) {
    $sa4 = (struct sockaddr_in *)args->uservaddr;
    printf("E|%llu|%d|%d|%s|4|%s|%d\n", nsecs, pid, tid, comm, ntop($sa4->sin_addr.s_addr), $sa4->sin_port);
  } else if ($family == 10) {
    $sa6 = (struct sockaddr_in6 *)args->uservaddr;
    printf("E|%llu|%d|%d|%s|6|%s|%d\n", nsecs, pid, tid, comm, ntop($sa6->sin6_addr.in6_u.u6_addr8), $sa6->sin6_port);
  }
}
"#;

    const BPFTRACE_SCRIPT_CONNECT_V4_ONLY: &str = r#"
tracepoint:syscalls:sys_enter_connect
/args->addrlen >= 16/
{
  $family = *(uint16*)args->uservaddr;
  if ($family == 2) {
    $sa4 = (struct sockaddr_in *)args->uservaddr;
    printf("E|%llu|%d|%d|%s|4|%s|%d\n", nsecs, pid, tid, comm, ntop($sa4->sin_addr.s_addr), $sa4->sin_port);
  }
}
"#;

    pub fn entrypoint() {
        std::panic::set_hook(Box::new(|panic_info| {
            log(LogLevel::Error, &format!("panic intercepted: {panic_info}"));
        }));

        let exit_code = match std::panic::catch_unwind(run) {
            Ok(Ok(())) => 0,
            Ok(Err(err)) => {
                log(LogLevel::Error, &format!("fatal error: {err}"));
                0
            }
            Err(_) => {
                log(
                    LogLevel::Error,
                    "panic escaped outer boundary (kept non-failing by design)",
                );
                0
            }
        };

        std::process::exit(exit_code);
    }

    fn run() -> Result<(), String> {
        let cfg = match Config::from_args(env::args().skip(1).collect()) {
            Ok(cfg) => cfg,
            Err(err) if err == "help" => return Ok(()),
            Err(err) => return Err(err),
        };

        log(LogLevel::Info, "starting linux egress agent");
        log(
            LogLevel::Info,
            &format!("output path: {}", cfg.output_path.display()),
        );

        if let Err(err) = install_signal_handlers() {
            log(
                LogLevel::Warn,
                &format!(
                    "signal handlers unavailable; graceful interrupt handling disabled: {err}"
                ),
            );
        }

        log(
            LogLevel::Info,
            "capture mode: background/foreground monitor (runs until interrupted with SIGINT/SIGTERM/SIGQUIT/SIGHUP)",
        );
        log(
            LogLevel::Info,
            "capture scope: system-wide tracepoint (captures host and container processes; no PID filters)",
        );

        let started_unix_nanos = unix_now_nanos();
        let started_at = Instant::now();

        let host_metadata = HostMetadata::discover();
        log(
            LogLevel::Info,
            &format!(
                "host: hostname={} kernel={}",
                host_metadata.hostname, host_metadata.kernel
            ),
        );

        let mut run_errors = Vec::new();

        let backend = match start_capture_backend(&cfg.bpftrace_path, cfg.verbose) {
            Ok(backend) => Some(backend),
            Err(err) => {
                let msg = format!("eBPF backend unavailable: {err}");
                log(LogLevel::Error, &msg);
                run_errors.push(msg);
                None
            }
        };

        let mut events = Vec::new();
        let mut dropped_events = 0usize;
        let mut dropped_lines = 0usize;
        let mut process_cache = ProcessCache::default();

        let mut backend_name = String::from("none");
        let mut backend = backend;
        let should_run_loop = backend.is_some();

        if let Some(b) = backend.as_ref() {
            backend_name = format!("bpftrace:{}:{}", b.launch_mode.name(), b.script_name);
            log(
                LogLevel::Info,
                &format!("capture backend attached: {backend_name}"),
            );
        }

        if let Some(ready_file_path) = cfg.ready_file_path.as_ref() {
            if should_run_loop {
                match write_ready_file(ready_file_path, &backend_name, started_unix_nanos) {
                    Ok(()) => {
                        log(
                            LogLevel::Info,
                            &format!("readiness marker written: {}", ready_file_path.display()),
                        );
                    }
                    Err(err) => {
                        let msg = format!(
                            "failed to write readiness marker {}: {err}",
                            ready_file_path.display()
                        );
                        log(LogLevel::Warn, &msg);
                        run_errors.push(msg);
                    }
                }
            } else {
                let msg = format!(
                    "readiness marker not written (backend unavailable): {}",
                    ready_file_path.display()
                );
                log(LogLevel::Warn, &msg);
                run_errors.push(msg);
            }
        }

        if !should_run_loop {
            let msg = String::from("nothing to monitor (capture backend is unavailable)");
            log(LogLevel::Warn, &msg);
            run_errors.push(msg);
        }

        if should_run_loop {
            loop {
                if shutdown_requested() {
                    log(
                        LogLevel::Info,
                        "termination signal received, stopping capture and writing summary",
                    );
                    break;
                }

                if let Some(b) = backend.as_mut() {
                    b.drain_pending_messages();

                    match b.child.try_wait() {
                        Ok(Some(status)) => {
                            let mut msg =
                                format!("capture backend exited early with status: {status}");
                            let stderr_summary = b.stderr_tail_summary();
                            if !stderr_summary.is_empty() {
                                let _ = write!(msg, " | stderr: {stderr_summary}");
                            }
                            log(LogLevel::Warn, &msg);
                            run_errors.push(msg);
                            if let Some(mut done) = backend.take() {
                                let _ = done.stop();
                            }
                            continue;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            let msg = format!("failed polling capture backend: {err}");
                            log(LogLevel::Warn, &msg);
                            run_errors.push(msg);
                            if let Some(mut done) = backend.take() {
                                let _ = done.stop();
                            }
                            continue;
                        }
                    }

                    match b.recv_message(Duration::from_millis(200)) {
                        Ok(CaptureMessage::StdoutLine(line)) => match parse_capture_line(&line) {
                            ParsedLine::Event(raw) => {
                                let lineage =
                                    process_cache.lineage_for_pid(raw.pid, MAX_LINEAGE_DEPTH);
                                let event = EgressEvent {
                                    unix_nanos: raw.unix_nanos,
                                    pid: raw.pid,
                                    tid: raw.tid,
                                    comm: raw.comm,
                                    family: if raw.family == 6 {
                                        String::from("ipv6")
                                    } else {
                                        String::from("ipv4")
                                    },
                                    destination: raw.destination,
                                    port: raw.port,
                                    lineage,
                                };

                                if events.len() < cfg.max_events {
                                    events.push(event);
                                } else {
                                    dropped_events = dropped_events.saturating_add(1);
                                }
                            }
                            ParsedLine::Ignored => {
                                if cfg.verbose {
                                    log(LogLevel::Debug, &format!("ignored capture line: {line}"));
                                }
                            }
                            ParsedLine::Invalid(reason) => {
                                dropped_lines = dropped_lines.saturating_add(1);
                                if cfg.verbose {
                                    log(LogLevel::Warn, &format!("invalid capture line: {reason}"));
                                }
                            }
                        },
                        Ok(CaptureMessage::StderrLine(line)) => {
                            b.push_stderr_tail(&line);
                            if cfg.verbose {
                                log(LogLevel::Debug, &format!("bpftrace: {line}"));
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            let mut msg = String::from("capture backend channel disconnected");
                            let stderr_summary = b.stderr_tail_summary();
                            if !stderr_summary.is_empty() {
                                let _ = write!(msg, " | stderr: {stderr_summary}");
                            }
                            log(LogLevel::Warn, &msg);
                            run_errors.push(msg);
                            backend = None;
                        }
                    }
                } else {
                    thread::sleep(Duration::from_millis(200));
                }

                if backend.is_none() {
                    let msg =
                        String::from("monitoring stopped: capture backend is no longer running");
                    log(LogLevel::Warn, &msg);
                    run_errors.push(msg);
                    break;
                }
            }
        }

        if let Some(mut b) = backend {
            if let Err(err) = b.stop() {
                let msg = format!("failed to stop capture backend cleanly: {err}");
                log(LogLevel::Warn, &msg);
                run_errors.push(msg);
            }

            let drain_deadline = Instant::now() + Duration::from_millis(700);
            while Instant::now() < drain_deadline {
                b.drain_pending_messages();

                let next_message = if let Some(message) = b.pending_messages.pop_front() {
                    Ok(message)
                } else {
                    b.rx.try_recv()
                };

                match next_message {
                    Ok(CaptureMessage::StdoutLine(line)) => match parse_capture_line(&line) {
                        ParsedLine::Event(raw) => {
                            let lineage = process_cache.lineage_for_pid(raw.pid, MAX_LINEAGE_DEPTH);
                            let event = EgressEvent {
                                unix_nanos: raw.unix_nanos,
                                pid: raw.pid,
                                tid: raw.tid,
                                comm: raw.comm,
                                family: if raw.family == 6 {
                                    String::from("ipv6")
                                } else {
                                    String::from("ipv4")
                                },
                                destination: raw.destination,
                                port: raw.port,
                                lineage,
                            };
                            if events.len() < cfg.max_events {
                                events.push(event);
                            } else {
                                dropped_events = dropped_events.saturating_add(1);
                            }
                        }
                        ParsedLine::Ignored => {}
                        ParsedLine::Invalid(_) => dropped_lines = dropped_lines.saturating_add(1),
                    },
                    Ok(CaptureMessage::StderrLine(line)) => {
                        b.push_stderr_tail(&line);
                    }
                    Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(20)),
                    Err(mpsc::TryRecvError::Disconnected) => break,
                }
            }
        }

        let finished_unix_nanos = unix_now_nanos();
        let duration_millis = started_at.elapsed().as_millis();

        let process_lineage_tree = build_process_lineage_tree(&events);

        let summary = RunSummary {
            schema_version: String::from("v1"),
            agent_name: String::from("egress-agent"),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            started_unix_nanos,
            finished_unix_nanos,
            duration_millis,
            capture_backend: backend_name,
            capture_scope: String::from("system-wide"),
            hostname: host_metadata.hostname,
            kernel: host_metadata.kernel,
            max_events: cfg.max_events,
            total_events: events.len(),
            dropped_events,
            dropped_lines,
            errors: run_errors,
            events,
            process_lineage_tree,
        };

        write_summary_json(&cfg.output_path, &summary)
            .map_err(|err| format!("failed to write summary json: {err}"))?;

        log(
            LogLevel::Info,
            &format!(
                "summary written: {} (events={}, dropped_events={}, dropped_lines={})",
                cfg.output_path.display(),
                summary.total_events,
                summary.dropped_events,
                summary.dropped_lines
            ),
        );

        Ok(())
    }

    #[derive(Debug, Clone)]
    struct Config {
        output_path: PathBuf,
        ready_file_path: Option<PathBuf>,
        max_events: usize,
        bpftrace_path: String,
        verbose: bool,
    }

    impl Config {
        fn from_args(args: Vec<String>) -> Result<Self, String> {
            let mut output_path = PathBuf::from("run-summary.json");
            let mut ready_file_path: Option<PathBuf> = None;
            let mut max_events = DEFAULT_MAX_EVENTS;
            let mut bpftrace_path = String::from("bpftrace");
            let mut verbose = false;

            let mut i = 0usize;
            while i < args.len() {
                let arg = &args[i];
                if arg == "--" {
                    return Err(String::from("the '-- <command ...>' mode has been removed"));
                }

                match arg.as_str() {
                    "-h" | "--help" => {
                        print_help();
                        return Err(String::from("help"));
                    }
                    "--output" => {
                        i += 1;
                        let value = args
                            .get(i)
                            .ok_or_else(|| String::from("--output requires a value"))?;
                        output_path = PathBuf::from(value);
                    }

                    "--ready-file" => {
                        i += 1;
                        let value = args
                            .get(i)
                            .ok_or_else(|| String::from("--ready-file requires a value"))?;
                        ready_file_path = Some(PathBuf::from(value));
                    }
                    "--max-events" => {
                        i += 1;
                        let value = args
                            .get(i)
                            .ok_or_else(|| String::from("--max-events requires a value"))?;
                        max_events = value
                            .parse::<usize>()
                            .map_err(|_| format!("invalid --max-events value: {value}"))?;
                    }
                    "--bpftrace" => {
                        i += 1;
                        let value = args
                            .get(i)
                            .ok_or_else(|| String::from("--bpftrace requires a value"))?;
                        bpftrace_path = value.clone();
                    }
                    "--verbose" => {
                        verbose = true;
                    }
                    unknown if unknown.starts_with('-') => {
                        return Err(format!("unknown argument: {unknown}"));
                    }
                    positional => {
                        return Err(format!(
                            "unexpected positional argument: {positional}; this agent accepts only flags"
                        ));
                    }
                }

                i += 1;
            }

            Ok(Self {
                output_path,
                ready_file_path,
                max_events,
                bpftrace_path,
                verbose,
            })
        }
    }

    fn print_help() {
        println!(
            "egress-agent\n\
             \n\
             Linux egress monitoring agent (eBPF via bpftrace)\n\
             \n\
             Usage:\n\
             egress-agent [OPTIONS]\n\
             \n\
             Runs until interrupted by a termination signal.\n\
             \n\
             Options:\n\
               --output <FILE>            Output JSON file path (default: run-summary.json)
               --ready-file <FILE>        Write readiness marker when eBPF backend is attached
               --max-events <N>           Max captured events kept in memory/output (default: 200000)
               --bpftrace <PATH>          bpftrace executable path (default: bpftrace)
               --verbose                  Verbose logs
               -h, --help                 Show this help
"
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum LogLevel {
        Debug,
        Info,
        Warn,
        Error,
    }

    fn log(level: LogLevel, message: &str) {
        let ts = unix_now_millis();
        let level_str = match level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };

        let line = format!("[{ts}] [{level_str}] {message}");
        match level {
            LogLevel::Debug | LogLevel::Info => {
                let mut out = io::stdout().lock();
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            }
            LogLevel::Warn | LogLevel::Error => {
                let mut out = io::stderr().lock();
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            }
        }
    }

    fn unix_now_nanos() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn unix_now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[derive(Debug, Clone)]
    struct HostMetadata {
        hostname: String,
        kernel: String,
    }

    impl HostMetadata {
        fn discover() -> Self {
            let hostname = read_trimmed("/proc/sys/kernel/hostname")
                .or_else(|| env::var("HOSTNAME").ok())
                .unwrap_or_else(|| String::from("unknown"));

            let kernel = read_trimmed("/proc/version").unwrap_or_else(|| String::from("unknown"));

            Self { hostname, kernel }
        }
    }

    fn read_trimmed(path: &str) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn write_ready_file(
        path: &Path,
        backend_name: &str,
        started_unix_nanos: u64,
    ) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut payload = String::new();
        let _ = write!(
            payload,
            "{{\"status\":\"ready\",\"capture_backend\":\"{}\",\"started_unix_nanos\":{},\"ready_unix_nanos\":{}}}",
            escape_json_string(backend_name),
            started_unix_nanos,
            unix_now_nanos()
        );

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, payload.as_bytes())?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    fn escape_json_string(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c if c.is_control() => {
                    let _ = write!(escaped, "\\u{:04x}", c as u32);
                }
                c => escaped.push(c),
            }
        }
        escaped
    }

    const BACKEND_STARTUP_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
    const BACKEND_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(50);
    const BACKEND_STOP_WAIT_TIMEOUT: Duration = Duration::from_millis(1000);
    const BACKEND_STOP_POLL_INTERVAL: Duration = Duration::from_millis(25);
    const BACKEND_STDERR_TAIL_MAX_LINES: usize = 48;

    #[derive(Debug, Clone, Copy)]
    enum BackendLaunchMode {
        Direct,
        Sudo,
    }

    impl BackendLaunchMode {
        fn name(self) -> &'static str {
            match self {
                Self::Direct => "direct",
                Self::Sudo => "sudo",
            }
        }

        fn build_command(self, bpftrace_path: &str) -> Command {
            match self {
                Self::Direct => Command::new(bpftrace_path),
                Self::Sudo => {
                    let mut cmd = Command::new("sudo");
                    cmd.arg("-n").arg("--").arg(bpftrace_path);
                    cmd
                }
            }
        }
    }

    #[derive(Debug)]
    struct CaptureBackend {
        script_name: &'static str,
        launch_mode: BackendLaunchMode,
        child: Child,
        rx: mpsc::Receiver<CaptureMessage>,
        pending_messages: VecDeque<CaptureMessage>,
        stderr_tail: VecDeque<String>,
        stdout_join: Option<thread::JoinHandle<()>>,
        stderr_join: Option<thread::JoinHandle<()>>,
    }

    impl CaptureBackend {
        fn stop(&mut self) -> io::Result<()> {
            match self.child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(err) = self.child.kill()
                        && err.kind() != io::ErrorKind::InvalidInput
                    {
                        return Err(err);
                    }

                    let deadline = Instant::now() + BACKEND_STOP_WAIT_TIMEOUT;
                    loop {
                        match self.child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) => {
                                if Instant::now() >= deadline {
                                    break;
                                }
                                thread::sleep(BACKEND_STOP_POLL_INTERVAL);
                            }
                            Err(err) => return Err(err),
                        }
                    }
                }
                Err(err) => return Err(err),
            }

            // Avoid blocking shutdown on reader threads that may still wait for EOF in edge
            // cases (for example, inherited pipe fds from nested launchers).
            let _ = self.stdout_join.take();
            let _ = self.stderr_join.take();

            Ok(())
        }

        fn recv_message(
            &mut self,
            timeout: Duration,
        ) -> Result<CaptureMessage, mpsc::RecvTimeoutError> {
            if let Some(message) = self.pending_messages.pop_front() {
                return Ok(message);
            }
            self.rx.recv_timeout(timeout)
        }

        fn drain_pending_messages(&mut self) {
            while let Ok(message) = self.rx.try_recv() {
                if let CaptureMessage::StderrLine(line) = &message {
                    self.push_stderr_tail(line);
                }
                self.pending_messages.push_back(message);
            }
        }

        fn push_stderr_tail(&mut self, line: &str) {
            if line.trim().is_empty() {
                return;
            }
            if self.stderr_tail.len() >= BACKEND_STDERR_TAIL_MAX_LINES {
                let _ = self.stderr_tail.pop_front();
            }
            self.stderr_tail.push_back(line.to_string());
        }

        fn stderr_tail_summary(&self) -> String {
            self.stderr_tail
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        }
    }

    #[derive(Debug)]
    enum CaptureMessage {
        StdoutLine(String),
        StderrLine(String),
    }

    fn start_capture_backend(bpftrace_path: &str, verbose: bool) -> Result<CaptureBackend, String> {
        let scripts = [
            ("connect-v4v6", BPFTRACE_SCRIPT_CONNECT_V4V6),
            ("connect-v4-only", BPFTRACE_SCRIPT_CONNECT_V4_ONLY),
        ];

        let launches = if env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
            [BackendLaunchMode::Sudo, BackendLaunchMode::Direct]
        } else {
            [BackendLaunchMode::Direct, BackendLaunchMode::Sudo]
        };

        let mut errors = Vec::new();

        for launch_mode in launches {
            for (script_name, script) in scripts {
                match spawn_bpftrace_backend(
                    bpftrace_path,
                    script,
                    script_name,
                    launch_mode,
                    verbose,
                ) {
                    Ok(backend) => return Ok(backend),
                    Err(err) => {
                        errors.push(format!("{}:{}: {err}", launch_mode.name(), script_name))
                    }
                }
            }
        }

        Err(errors.join(" | "))
    }

    fn spawn_bpftrace_backend(
        bpftrace_path: &str,
        script: &str,
        script_name: &'static str,
        launch_mode: BackendLaunchMode,
        verbose: bool,
    ) -> Result<CaptureBackend, String> {
        let mut command = launch_mode.build_command(bpftrace_path);
        command
            .arg("-q")
            .arg("-e")
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| format!("spawn failed: {err}"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| String::from("missing stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| String::from("missing stderr pipe"))?;

        let (tx, rx) = mpsc::channel::<CaptureMessage>();

        let tx_out = tx.clone();
        let stdout_join = thread::spawn(move || {
            stream_lines(stdout, move |line| {
                let _ = tx_out.send(CaptureMessage::StdoutLine(line));
            });
        });

        let tx_err = tx.clone();
        let stderr_join = thread::spawn(move || {
            stream_lines(stderr, move |line| {
                let _ = tx_err.send(CaptureMessage::StderrLine(line));
            });
        });

        if verbose {
            log(
                LogLevel::Debug,
                &format!(
                    "spawned bpftrace backend with script {} using {} launch",
                    script_name,
                    launch_mode.name()
                ),
            );
        }

        let mut backend = CaptureBackend {
            script_name,
            launch_mode,
            child,
            rx,
            pending_messages: VecDeque::new(),
            stderr_tail: VecDeque::new(),
            stdout_join: Some(stdout_join),
            stderr_join: Some(stderr_join),
        };

        wait_for_backend_startup(&mut backend)?;

        Ok(backend)
    }

    fn wait_for_backend_startup(backend: &mut CaptureBackend) -> Result<(), String> {
        let deadline = Instant::now() + BACKEND_STARTUP_PROBE_TIMEOUT;

        loop {
            backend.drain_pending_messages();

            match backend.child.try_wait() {
                Ok(Some(status)) => {
                    let stderr = backend.stderr_tail_summary();
                    let _ = backend.stop();
                    let mut message = format!("exited during startup with status: {status}");
                    if !stderr.is_empty() {
                        let _ = write!(message, " | stderr: {stderr}");
                    }
                    return Err(message);
                }
                Ok(None) => {}
                Err(err) => {
                    let _ = backend.stop();
                    return Err(format!("failed probing startup status: {err}"));
                }
            }

            if Instant::now() >= deadline {
                break;
            }

            thread::sleep(BACKEND_STARTUP_POLL_INTERVAL);
        }

        Ok(())
    }

    fn stream_lines<R, F>(reader: R, mut on_line: F)
    where
        R: Read,
        F: FnMut(String),
    {
        let mut buf_reader = BufReader::new(reader);
        loop {
            let mut line = String::new();
            match buf_reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let line = line.trim_end_matches(['\n', '\r']).to_string();
                    on_line(line);
                }
                Err(_) => break,
            }
        }
    }

    #[derive(Debug)]
    struct RawEgressEvent {
        unix_nanos: u64,
        pid: u32,
        tid: u32,
        comm: String,
        family: u8,
        destination: String,
        port: u16,
    }

    enum ParsedLine {
        Event(RawEgressEvent),
        Ignored,
        Invalid(String),
    }

    fn parse_capture_line(line: &str) -> ParsedLine {
        if !line.starts_with("E|") {
            return ParsedLine::Ignored;
        }

        let parts: Vec<&str> = line.splitn(8, '|').collect();
        if parts.len() != 8 {
            return ParsedLine::Invalid(format!("expected 8 fields, got {}: {line}", parts.len()));
        }

        let parse_u64 = |v: &str, name: &str| -> Result<u64, String> {
            v.parse::<u64>()
                .map_err(|_| format!("invalid {name} in line: {line}"))
        };
        let parse_u32 = |v: &str, name: &str| -> Result<u32, String> {
            v.parse::<u32>()
                .map_err(|_| format!("invalid {name} in line: {line}"))
        };

        let unix_nanos = match parse_u64(parts[1], "unix_nanos") {
            Ok(v) => v,
            Err(err) => return ParsedLine::Invalid(err),
        };
        let pid = match parse_u32(parts[2], "pid") {
            Ok(v) => v,
            Err(err) => return ParsedLine::Invalid(err),
        };
        let tid = match parse_u32(parts[3], "tid") {
            Ok(v) => v,
            Err(err) => return ParsedLine::Invalid(err),
        };

        let comm = parts[4].to_string();
        let family = match parts[5] {
            "4" => 4,
            "6" => 6,
            _ => return ParsedLine::Invalid(format!("invalid ip family in line: {line}")),
        };

        let destination = parts[6].to_string();
        let raw_port = match parts[7].parse::<u16>() {
            Ok(v) => v,
            Err(_) => {
                return ParsedLine::Invalid(format!("invalid destination port in line: {line}"));
            }
        };
        let port = u16::from_be(raw_port);

        ParsedLine::Event(RawEgressEvent {
            unix_nanos,
            pid,
            tid,
            comm,
            family,
            destination,
            port,
        })
    }

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    struct ProcessKey {
        pid: u32,
        start_time_ticks: Option<u64>,
    }

    #[derive(Debug, Clone)]
    struct ProcessInfo {
        key: ProcessKey,
        ppid: u32,
        name: String,
        cmdline: String,
        exe: String,
    }

    #[derive(Debug, Default)]
    struct ProcessCache {
        by_key: HashMap<ProcessKey, ProcessInfo>,
        last_by_pid: HashMap<u32, ProcessKey>,
    }

    impl ProcessCache {
        fn lineage_for_pid(&mut self, pid: u32, max_depth: usize) -> Vec<ProcessInfo> {
            let mut chain = Vec::new();
            let mut current_pid = pid;
            let mut seen_pids = HashSet::new();

            for _ in 0..max_depth {
                if !seen_pids.insert(current_pid) {
                    break;
                }

                let info = match self.get_or_refresh(current_pid) {
                    Some(i) => i,
                    None => break,
                };

                let parent_pid = info.ppid;
                chain.push(info);

                if parent_pid == 0 || parent_pid == current_pid {
                    break;
                }

                current_pid = parent_pid;
            }

            chain.reverse();
            chain
        }

        fn get_or_refresh(&mut self, pid: u32) -> Option<ProcessInfo> {
            if let Some(info) = read_process_info(pid) {
                self.last_by_pid.insert(pid, info.key.clone());
                self.by_key.insert(info.key.clone(), info.clone());
                return Some(info);
            }

            let key = self.last_by_pid.get(&pid)?;
            self.by_key.get(key).cloned()
        }
    }

    fn read_process_info(pid: u32) -> Option<ProcessInfo> {
        let status_path = format!("/proc/{pid}/status");
        let status = fs::read_to_string(status_path).ok()?;

        let mut ppid = None;
        let mut name = None;

        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Name:") {
                let n = v.trim();
                if !n.is_empty() {
                    name = Some(n.to_string());
                }
                continue;
            }
            if let Some(v) = line.strip_prefix("PPid:") {
                let parsed = v.trim().parse::<u32>().ok();
                if parsed.is_some() {
                    ppid = parsed;
                }
                continue;
            }
        }

        let name = name.unwrap_or_else(|| String::from("unknown"));
        let ppid = ppid.unwrap_or(0);

        let cmdline_path = format!("/proc/{pid}/cmdline");
        let cmdline = fs::read(cmdline_path)
            .ok()
            .and_then(|bytes| parse_cmdline_bytes(&bytes))
            .unwrap_or_else(|| name.clone());

        let exe_path = format!("/proc/{pid}/exe");
        let exe = fs::read_link(exe_path)
            .ok()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let start_time_ticks = read_process_start_time_ticks(pid);

        Some(ProcessInfo {
            key: ProcessKey {
                pid,
                start_time_ticks,
            },
            ppid,
            name,
            cmdline,
            exe,
        })
    }

    fn parse_cmdline_bytes(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }

        let parts: Vec<String> = bytes
            .split(|b| *b == 0)
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();

        if parts.is_empty() {
            return None;
        }

        Some(parts.join(" "))
    }

    fn read_process_start_time_ticks(pid: u32) -> Option<u64> {
        let stat_path = format!("/proc/{pid}/stat");
        let stat = fs::read_to_string(stat_path).ok()?;

        let close_paren = stat.rfind(')')?;
        let after = stat.get(close_paren + 2..)?;
        let fields: Vec<&str> = after.split_whitespace().collect();

        let start_time_index_from_after = 19usize;
        fields
            .get(start_time_index_from_after)
            .and_then(|v| v.parse::<u64>().ok())
    }

    #[derive(Debug, Clone)]
    struct EgressEvent {
        unix_nanos: u64,
        pid: u32,
        tid: u32,
        comm: String,
        family: String,
        destination: String,
        port: u16,
        lineage: Vec<ProcessInfo>,
    }

    #[derive(Debug, Clone)]
    struct ProcessTreeNode {
        key: ProcessKey,
        ppid: u32,
        name: String,
        cmdline: String,
        exe: String,
        direct_egress_events: u64,
        total_egress_events: u64,
        children: Vec<ProcessTreeNode>,
    }

    fn build_process_lineage_tree(events: &[EgressEvent]) -> Vec<ProcessTreeNode> {
        #[derive(Debug, Clone)]
        struct FlatNode {
            key: ProcessKey,
            ppid: u32,
            parent_key: Option<ProcessKey>,
            name: String,
            cmdline: String,
            exe: String,
            direct: u64,
            total: u64,
            child_keys: Vec<ProcessKey>,
        }

        let mut flat: HashMap<ProcessKey, FlatNode> = HashMap::new();

        for event in events {
            if event.lineage.is_empty() {
                continue;
            }

            for (idx, process) in event.lineage.iter().enumerate() {
                let key = process.key.clone();
                let parent_key = if idx > 0 {
                    Some(event.lineage[idx - 1].key.clone())
                } else {
                    None
                };

                let entry = flat.entry(key.clone()).or_insert_with(|| FlatNode {
                    key: key.clone(),
                    ppid: process.ppid,
                    parent_key: parent_key.clone(),
                    name: process.name.clone(),
                    cmdline: process.cmdline.clone(),
                    exe: process.exe.clone(),
                    direct: 0,
                    total: 0,
                    child_keys: Vec::new(),
                });

                entry.total = entry.total.saturating_add(1);
                if idx + 1 == event.lineage.len() {
                    entry.direct = entry.direct.saturating_add(1);
                }

                if entry.parent_key.is_none() {
                    entry.parent_key = parent_key;
                }
            }
        }

        let keys: Vec<ProcessKey> = flat.keys().cloned().collect();
        for key in &keys {
            let parent_key = flat.get(key).and_then(|n| n.parent_key.clone());
            if let Some(parent_key) = parent_key
                && let Some(parent) = flat.get_mut(&parent_key)
                && !parent.child_keys.contains(key)
            {
                parent.child_keys.push(key.clone());
            }
        }

        fn sort_keys_for_output(keys: &mut [ProcessKey], flat: &HashMap<ProcessKey, FlatNode>) {
            keys.sort_by(|a, b| {
                let na = flat.get(a);
                let nb = flat.get(b);
                match (na, nb) {
                    (Some(na), Some(nb)) => nb
                        .total
                        .cmp(&na.total)
                        .then_with(|| na.key.pid.cmp(&nb.key.pid)),
                    _ => a.pid.cmp(&b.pid),
                }
            });
        }

        fn build_node(
            key: &ProcessKey,
            flat: &HashMap<ProcessKey, FlatNode>,
        ) -> Option<ProcessTreeNode> {
            let node = flat.get(key)?;
            let mut children_keys = node.child_keys.clone();
            sort_keys_for_output(&mut children_keys, flat);

            let children = children_keys
                .iter()
                .filter_map(|child_key| build_node(child_key, flat))
                .collect();

            Some(ProcessTreeNode {
                key: node.key.clone(),
                ppid: node.ppid,
                name: node.name.clone(),
                cmdline: node.cmdline.clone(),
                exe: node.exe.clone(),
                direct_egress_events: node.direct,
                total_egress_events: node.total,
                children,
            })
        }

        let mut roots: Vec<ProcessKey> = flat
            .values()
            .filter(|n| {
                if let Some(parent_key) = &n.parent_key {
                    !flat.contains_key(parent_key)
                } else {
                    true
                }
            })
            .map(|n| n.key.clone())
            .collect();

        sort_keys_for_output(&mut roots, &flat);

        roots
            .iter()
            .filter_map(|root_key| build_node(root_key, &flat))
            .collect()
    }

    #[derive(Debug, Clone)]
    struct RunSummary {
        schema_version: String,
        agent_name: String,
        agent_version: String,
        started_unix_nanos: u64,
        finished_unix_nanos: u64,
        duration_millis: u128,
        capture_backend: String,
        capture_scope: String,
        hostname: String,
        kernel: String,
        max_events: usize,
        total_events: usize,
        dropped_events: usize,
        dropped_lines: usize,
        errors: Vec<String>,
        events: Vec<EgressEvent>,
        process_lineage_tree: Vec<ProcessTreeNode>,
    }

    fn write_summary_json(path: &Path, summary: &RunSummary) -> io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        writer.write_all(b"{\n")?;
        write_kv_string(
            &mut writer,
            1,
            "schema_version",
            &summary.schema_version,
            true,
        )?;
        write_kv_string(&mut writer, 1, "agent_name", &summary.agent_name, true)?;
        write_kv_string(
            &mut writer,
            1,
            "agent_version",
            &summary.agent_version,
            true,
        )?;
        write_kv_u64(
            &mut writer,
            1,
            "started_unix_nanos",
            summary.started_unix_nanos,
            true,
        )?;
        write_kv_u64(
            &mut writer,
            1,
            "finished_unix_nanos",
            summary.finished_unix_nanos,
            true,
        )?;
        write_kv_u128(
            &mut writer,
            1,
            "duration_millis",
            summary.duration_millis,
            true,
        )?;
        write_kv_string(
            &mut writer,
            1,
            "capture_backend",
            &summary.capture_backend,
            true,
        )?;
        write_kv_string(
            &mut writer,
            1,
            "capture_scope",
            &summary.capture_scope,
            true,
        )?;
        write_kv_string(&mut writer, 1, "hostname", &summary.hostname, true)?;
        write_kv_string(&mut writer, 1, "kernel", &summary.kernel, true)?;

        write_kv_usize(&mut writer, 1, "max_events", summary.max_events, true)?;
        write_kv_usize(&mut writer, 1, "total_events", summary.total_events, true)?;
        write_kv_usize(
            &mut writer,
            1,
            "dropped_events",
            summary.dropped_events,
            true,
        )?;
        write_kv_usize(&mut writer, 1, "dropped_lines", summary.dropped_lines, true)?;

        indent(&mut writer, 1)?;
        writer.write_all(b"\"errors\": [\n")?;
        for (idx, err) in summary.errors.iter().enumerate() {
            indent(&mut writer, 2)?;
            write_json_string(&mut writer, err)?;
            if idx + 1 != summary.errors.len() {
                writer.write_all(b",")?;
            }
            writer.write_all(b"\n")?;
        }
        indent(&mut writer, 1)?;
        writer.write_all(b"],\n")?;

        indent(&mut writer, 1)?;
        writer.write_all(b"\"events\": [\n")?;
        for (event_idx, event) in summary.events.iter().enumerate() {
            write_event_json(&mut writer, event, 2)?;
            if event_idx + 1 != summary.events.len() {
                writer.write_all(b",")?;
            }
            writer.write_all(b"\n")?;
        }
        indent(&mut writer, 1)?;
        writer.write_all(b"],\n")?;

        indent(&mut writer, 1)?;
        writer.write_all(b"\"process_lineage_tree\": [\n")?;
        for (idx, root) in summary.process_lineage_tree.iter().enumerate() {
            write_process_tree_json(&mut writer, root, 2)?;
            if idx + 1 != summary.process_lineage_tree.len() {
                writer.write_all(b",")?;
            }
            writer.write_all(b"\n")?;
        }
        indent(&mut writer, 1)?;
        writer.write_all(b"]\n")?;

        writer.write_all(b"}\n")?;
        writer.flush()
    }

    fn write_event_json<W: Write>(
        writer: &mut W,
        event: &EgressEvent,
        indent_level: usize,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        writer.write_all(b"{\n")?;
        write_kv_u64(
            writer,
            indent_level + 1,
            "unix_nanos",
            event.unix_nanos,
            true,
        )?;
        write_kv_u32(writer, indent_level + 1, "pid", event.pid, true)?;
        write_kv_u32(writer, indent_level + 1, "tid", event.tid, true)?;
        write_kv_string(writer, indent_level + 1, "comm", &event.comm, true)?;
        write_kv_string(writer, indent_level + 1, "family", &event.family, true)?;
        write_kv_string(
            writer,
            indent_level + 1,
            "destination",
            &event.destination,
            true,
        )?;
        write_kv_u16(writer, indent_level + 1, "port", event.port, true)?;

        indent(writer, indent_level + 1)?;
        writer.write_all(b"\"lineage\": [\n")?;
        for (idx, process) in event.lineage.iter().enumerate() {
            indent(writer, indent_level + 2)?;
            writer.write_all(b"{")?;
            writer.write_all(b"\"pid\": ")?;
            write!(writer, "{}", process.key.pid)?;
            writer.write_all(b", \"ppid\": ")?;
            write!(writer, "{}", process.ppid)?;
            writer.write_all(b", \"start_time_ticks\": ")?;
            if let Some(v) = process.key.start_time_ticks {
                write!(writer, "{v}")?;
            } else {
                writer.write_all(b"null")?;
            }
            writer.write_all(b", \"name\": ")?;
            write_json_string(writer, &process.name)?;
            writer.write_all(b", \"cmdline\": ")?;
            write_json_string(writer, &process.cmdline)?;
            writer.write_all(b", \"exe\": ")?;
            write_json_string(writer, &process.exe)?;
            writer.write_all(b"}")?;
            if idx + 1 != event.lineage.len() {
                writer.write_all(b",")?;
            }
            writer.write_all(b"\n")?;
        }
        indent(writer, indent_level + 1)?;
        writer.write_all(b"]\n")?;

        indent(writer, indent_level)?;
        writer.write_all(b"}")
    }

    fn write_process_tree_json<W: Write>(
        writer: &mut W,
        node: &ProcessTreeNode,
        indent_level: usize,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        writer.write_all(b"{\n")?;

        write_kv_u32(writer, indent_level + 1, "pid", node.key.pid, true)?;
        write_kv_u32(writer, indent_level + 1, "ppid", node.ppid, true)?;

        indent(writer, indent_level + 1)?;
        writer.write_all(b"\"start_time_ticks\": ")?;
        if let Some(v) = node.key.start_time_ticks {
            write!(writer, "{v}")?;
        } else {
            writer.write_all(b"null")?;
        }
        writer.write_all(b",\n")?;

        write_kv_string(writer, indent_level + 1, "name", &node.name, true)?;
        write_kv_string(writer, indent_level + 1, "cmdline", &node.cmdline, true)?;
        write_kv_string(writer, indent_level + 1, "exe", &node.exe, true)?;
        write_kv_u64(
            writer,
            indent_level + 1,
            "direct_egress_events",
            node.direct_egress_events,
            true,
        )?;
        write_kv_u64(
            writer,
            indent_level + 1,
            "total_egress_events",
            node.total_egress_events,
            true,
        )?;

        indent(writer, indent_level + 1)?;
        writer.write_all(b"\"children\": [\n")?;
        for (idx, child) in node.children.iter().enumerate() {
            write_process_tree_json(writer, child, indent_level + 2)?;
            if idx + 1 != node.children.len() {
                writer.write_all(b",")?;
            }
            writer.write_all(b"\n")?;
        }
        indent(writer, indent_level + 1)?;
        writer.write_all(b"]\n")?;

        indent(writer, indent_level)?;
        writer.write_all(b"}")
    }

    fn write_kv_string<W: Write>(
        writer: &mut W,
        indent_level: usize,
        key: &str,
        value: &str,
        trailing_comma: bool,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        write_json_string(writer, key)?;
        writer.write_all(b": ")?;
        write_json_string(writer, value)?;
        if trailing_comma {
            writer.write_all(b",\n")
        } else {
            writer.write_all(b"\n")
        }
    }

    fn write_kv_u64<W: Write>(
        writer: &mut W,
        indent_level: usize,
        key: &str,
        value: u64,
        trailing_comma: bool,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        write_json_string(writer, key)?;
        writer.write_all(b": ")?;
        write!(writer, "{value}")?;
        if trailing_comma {
            writer.write_all(b",\n")
        } else {
            writer.write_all(b"\n")
        }
    }

    fn write_kv_u128<W: Write>(
        writer: &mut W,
        indent_level: usize,
        key: &str,
        value: u128,
        trailing_comma: bool,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        write_json_string(writer, key)?;
        writer.write_all(b": ")?;
        write!(writer, "{value}")?;
        if trailing_comma {
            writer.write_all(b",\n")
        } else {
            writer.write_all(b"\n")
        }
    }

    fn write_kv_u32<W: Write>(
        writer: &mut W,
        indent_level: usize,
        key: &str,
        value: u32,
        trailing_comma: bool,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        write_json_string(writer, key)?;
        writer.write_all(b": ")?;
        write!(writer, "{value}")?;
        if trailing_comma {
            writer.write_all(b",\n")
        } else {
            writer.write_all(b"\n")
        }
    }

    fn write_kv_u16<W: Write>(
        writer: &mut W,
        indent_level: usize,
        key: &str,
        value: u16,
        trailing_comma: bool,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        write_json_string(writer, key)?;
        writer.write_all(b": ")?;
        write!(writer, "{value}")?;
        if trailing_comma {
            writer.write_all(b",\n")
        } else {
            writer.write_all(b"\n")
        }
    }

    fn write_kv_usize<W: Write>(
        writer: &mut W,
        indent_level: usize,
        key: &str,
        value: usize,
        trailing_comma: bool,
    ) -> io::Result<()> {
        indent(writer, indent_level)?;
        write_json_string(writer, key)?;
        writer.write_all(b": ")?;
        write!(writer, "{value}")?;
        if trailing_comma {
            writer.write_all(b",\n")
        } else {
            writer.write_all(b"\n")
        }
    }

    fn write_json_string<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
        writer.write_all(b"\"")?;

        let mut escaped = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c if c.is_control() => {
                    let _ = write!(escaped, "\\u{:04x}", c as u32);
                }
                c => escaped.push(c),
            }
        }

        writer.write_all(escaped.as_bytes())?;
        writer.write_all(b"\"")
    }

    fn indent<W: Write>(writer: &mut W, level: usize) -> io::Result<()> {
        for _ in 0..level {
            writer.write_all(b"  ")?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_capture_line_v4() {
            let line = "E|123456789|42|42|curl|4|1.2.3.4|443";
            match parse_capture_line(line) {
                ParsedLine::Event(ev) => {
                    assert_eq!(ev.unix_nanos, 123456789);
                    assert_eq!(ev.pid, 42);
                    assert_eq!(ev.family, 4);
                    assert_eq!(ev.destination, "1.2.3.4");
                    assert_eq!(ev.port, 443);
                }
                _ => panic!("expected event"),
            }
        }

        #[test]
        fn parse_cmdline_handles_null_separated_values() {
            let input = b"python\0script.py\0--flag\0";
            let parsed = parse_cmdline_bytes(input);
            assert_eq!(parsed.as_deref(), Some("python script.py --flag"));
        }

        #[test]
        fn json_escape_works() {
            let mut out = Vec::new();
            write_json_string(&mut out, "a\n\"b\"").expect("json string should serialize");
            let s = String::from_utf8(out).expect("valid utf8");
            assert_eq!(s, "\"a\\n\\\"b\\\"\"");
        }
    }
}
