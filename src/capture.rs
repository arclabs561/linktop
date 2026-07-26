use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Local;
use clap::ValueEnum;
use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};

use crate::model::{
    Address, App, Health, LinkSnapshot, MacScope, MonitorControl, MonitorMode, MonitorUpdate, Peer,
    PeerSnapshot, ProbePolicy,
};
use crate::{
    InteractionOutcome, InteractionState, apply_monitor_update, apply_tui_key, history, net,
    process, ui,
};

const POLL_STEP: Duration = Duration::from_millis(100);
const NATIVE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_RENDER_SETTLE: Duration = Duration::from_millis(200);
const SCREENSHOT_CHILD_SCENE: &str = "LINKTOP_SCREENSHOT_CHILD_SCENE";
const DENSE_SCENE_GATEWAY: &str = "192.0.2.1";
const DEFAULT_BACKGROUND: &str = "#11161c";
const DEFAULT_FOREGROUND: &str = "#c0cad6";
const CELL_WIDTH: u32 = 9;
const CELL_HEIGHT: u32 = 18;
const PADDING: u32 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureSize {
    pub columns: u16,
    pub rows: u16,
}

impl fmt::Display for CaptureSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}x{}", self.columns, self.rows)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaptureScene {
    DensePeers,
}

impl CaptureScene {
    fn label(self) -> &'static str {
        match self {
            Self::DensePeers => "dense-peers",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayKey {
    Refresh,
    Pause,
    Active,
    Overview,
    Link,
    Peers,
    Tab,
    Down,
    Up,
    PageDown,
    PageUp,
    Home,
    End,
    Quit,
    Escape,
}

impl ReplayKey {
    fn key_code(self) -> KeyCode {
        match self {
            Self::Refresh => KeyCode::Char('r'),
            Self::Pause => KeyCode::Char('p'),
            Self::Active => KeyCode::Char('a'),
            Self::Overview => KeyCode::Char('1'),
            Self::Link => KeyCode::Char('2'),
            Self::Peers => KeyCode::Char('3'),
            Self::Tab => KeyCode::Tab,
            Self::Down => KeyCode::Down,
            Self::Up => KeyCode::Up,
            Self::PageDown => KeyCode::PageDown,
            Self::PageUp => KeyCode::PageUp,
            Self::Home => KeyCode::Home,
            Self::End => KeyCode::End,
            Self::Quit => KeyCode::Char('q'),
            Self::Escape => KeyCode::Esc,
        }
    }

    fn tmux_key(self) -> NativeKey<'static> {
        match self {
            Self::Refresh => NativeKey::Literal("r"),
            Self::Pause => NativeKey::Literal("p"),
            Self::Active => NativeKey::Literal("a"),
            Self::Overview => NativeKey::Literal("1"),
            Self::Link => NativeKey::Literal("2"),
            Self::Peers => NativeKey::Literal("3"),
            Self::Tab => NativeKey::Named("Tab"),
            Self::Down => NativeKey::Named("Down"),
            Self::Up => NativeKey::Named("Up"),
            Self::PageDown => NativeKey::Named("NPage"),
            Self::PageUp => NativeKey::Named("PPage"),
            Self::Home => NativeKey::Named("Home"),
            Self::End => NativeKey::Named("End"),
            Self::Quit => NativeKey::Literal("q"),
            Self::Escape => NativeKey::Named("Escape"),
        }
    }
}

impl FromStr for ReplayKey {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "r" => Ok(Self::Refresh),
            "p" => Ok(Self::Pause),
            "a" => Ok(Self::Active),
            "1" => Ok(Self::Overview),
            "2" => Ok(Self::Link),
            "3" => Ok(Self::Peers),
            "tab" => Ok(Self::Tab),
            "j" | "down" => Ok(Self::Down),
            "k" | "up" => Ok(Self::Up),
            "page-down" => Ok(Self::PageDown),
            "page-up" => Ok(Self::PageUp),
            "g" | "home" => Ok(Self::Home),
            "G" | "end" => Ok(Self::End),
            "q" => Ok(Self::Quit),
            "esc" | "escape" => Ok(Self::Escape),
            _ => Err(format!(
                "unknown replay key {value:?}; expected r, p, a, 1, 2, 3, tab, j, k, up, down, page-up, page-down, g, G, home, or end"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledKey {
    at: Duration,
    key: ReplayKey,
}

impl FromStr for ScheduledKey {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (at, key) = split_schedule_value(value, "key")?;
        Ok(Self {
            at: parse_action_time(at)?,
            key: key.parse()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledResize {
    at: Duration,
    size: CaptureSize,
}

impl FromStr for ScheduledResize {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (at, size) = split_schedule_value(value, "resize")?;
        let (columns, rows) = size
            .split_once(['x', 'X'])
            .ok_or_else(|| "resize must use AT:COLSxROWS".to_string())?;
        let columns = parse_u16_bound(columns, "columns", 60, 300)?;
        let rows = parse_u16_bound(rows, "rows", 10, 100)?;
        Ok(Self {
            at: parse_action_time(at)?,
            size: CaptureSize { columns, rows },
        })
    }
}

fn split_schedule_value<'a>(
    value: &'a str,
    kind: &str,
) -> std::result::Result<(&'a str, &'a str), String> {
    value
        .split_once(':')
        .filter(|(at, action)| !at.is_empty() && !action.is_empty())
        .ok_or_else(|| format!("{kind} schedule must use AT:VALUE"))
}

fn parse_action_time(value: &str) -> std::result::Result<Duration, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| format!("elapsed time {value:?} is not an integer second"))?;
    if !(1..=86_400).contains(&seconds) {
        return Err("elapsed time must be between 1 and 86400 seconds".into());
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_u16_bound(
    value: &str,
    label: &str,
    minimum: u16,
    maximum: u16,
) -> std::result::Result<u16, String> {
    let value = value
        .parse::<u16>()
        .map_err(|_| format!("{label} must be an integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{label} must be between {minimum} and {maximum}"));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayPlan {
    frames: BTreeSet<Duration>,
    keys: BTreeMap<Duration, Vec<ReplayKey>>,
    resizes: BTreeMap<Duration, CaptureSize>,
    timestamps: Vec<Duration>,
}

impl ReplayPlan {
    fn new(
        requested_seconds: &[u64],
        keys: &[ScheduledKey],
        resizes: &[ScheduledResize],
        scene: Option<CaptureScene>,
    ) -> Result<Self> {
        let schedule = CaptureSchedule::new(requested_seconds)?;
        let frames: BTreeSet<_> = schedule.targets.into_iter().collect();
        let final_frame = *frames
            .last()
            .expect("validated capture schedule is nonempty");
        let mut scheduled_keys: BTreeMap<Duration, Vec<ReplayKey>> = BTreeMap::new();
        for scheduled in keys {
            anyhow::ensure!(
                scheduled.at <= final_frame,
                "scheduled key at {}s is after the final frame at {}s",
                scheduled.at.as_secs(),
                final_frame.as_secs()
            );
            anyhow::ensure!(
                !matches!(scheduled.key, ReplayKey::Quit | ReplayKey::Escape),
                "terminating keys q and esc cannot be replayed by a bounded screenshot transaction"
            );
            anyhow::ensure!(
                !(scene.is_some() && scheduled.key == ReplayKey::Active),
                "the dense-peers scene cannot replay `a` because synthetic scenes are passive"
            );
            scheduled_keys
                .entry(scheduled.at)
                .or_default()
                .push(scheduled.key);
        }
        let mut scheduled_resizes = BTreeMap::new();
        for scheduled in resizes {
            anyhow::ensure!(
                scheduled.at <= final_frame,
                "scheduled resize at {}s is after the final frame at {}s",
                scheduled.at.as_secs(),
                final_frame.as_secs()
            );
            if let Some(existing) = scheduled_resizes.insert(scheduled.at, scheduled.size) {
                anyhow::ensure!(
                    existing == scheduled.size,
                    "conflicting resizes at {}s: {existing} and {}",
                    scheduled.at.as_secs(),
                    scheduled.size
                );
            }
        }
        let timestamps = frames
            .iter()
            .chain(scheduled_keys.keys())
            .chain(scheduled_resizes.keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Self {
            frames,
            keys: scheduled_keys,
            resizes: scheduled_resizes,
            timestamps,
        })
    }

    fn final_frame(&self) -> Duration {
        *self
            .frames
            .last()
            .expect("validated replay plan is nonempty")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeKey<'a> {
    Literal(&'a str),
    Named(&'a str),
}

pub struct CaptureRequest {
    pub interval: Duration,
    pub mode: MonitorMode,
    pub probe_policy: ProbePolicy,
    pub requested_seconds: Vec<u64>,
    pub size: CaptureSize,
    pub output_directory: PathBuf,
    pub keys: Vec<ScheduledKey>,
    pub resizes: Vec<ScheduledResize>,
    pub scene: Option<CaptureScene>,
}

struct FrameName<'a> {
    subject: &'a str,
    scene: Option<CaptureScene>,
    session: &'a str,
    native: bool,
    index: usize,
    size: CaptureSize,
    scheduled: Duration,
    actual: Duration,
}

impl FrameName<'_> {
    fn stem(&self) -> String {
        format!(
            "{}-{}-{}{}-frame{:03}-{}-scheduled{:08}ms-actual{:08}ms",
            self.subject,
            self.scene.map_or("live", CaptureScene::label),
            self.session,
            if self.native { "-native" } else { "" },
            self.index,
            self.size,
            self.scheduled.as_millis(),
            self.actual.as_millis()
        )
    }
}

pub fn run(request: CaptureRequest) -> Result<()> {
    let CaptureRequest {
        interval,
        mode,
        probe_policy,
        requested_seconds,
        size,
        output_directory,
        keys,
        resizes,
        scene,
    } = request;
    let plan = ReplayPlan::new(&requested_seconds, &keys, &resizes, scene)?;
    fs::create_dir_all(&output_directory)
        .with_context(|| format!("create capture directory {}", output_directory.display()))?;
    private_directory(&output_directory)?;

    let session = format!(
        "{}-{}",
        Local::now().format("%Y%m%dT%H%M%S"),
        std::process::id()
    );
    let subject = subject_name(mode);
    let backend = TestBackend::new(size.columns, size.rows);
    let mut terminal = Terminal::new(backend).context("create capture terminal")?;
    let (updates, controls, monitor) = if scene.is_some() {
        start_scene_monitor()
    } else {
        net::start_monitor(interval, mode, probe_policy)
    };
    let started_at = Instant::now();
    let mut app = App::with_probe_policy(probe_policy);
    let mut interaction = InteractionState {
        active_mode: mode,
        peer_offset: 0,
        can_navigate: mode == MonitorMode::Overview,
    };
    let mut current_size = size;
    let mut frame_index = 0_usize;
    let result = (|| -> Result<()> {
        for target in plan.timestamps {
            wait_until(target, started_at, &updates, &mut app, None)?;
            drain_updates(&updates, &mut app, None)?;
            if let Some(scene) = scene {
                ensure_scene(&mut app, scene);
            }
            if let Some(size) = plan.resizes.get(&target).copied() {
                resize_terminal(&mut terminal, size)?;
                current_size = size;
            }
            if let Some(keys) = plan.keys.get(&target) {
                for key in keys {
                    let outcome = apply_tui_key(
                        &mut app,
                        &controls,
                        &mut interaction,
                        key.key_code(),
                        ui::peer_page_capacity(Rect::new(
                            0,
                            0,
                            current_size.columns,
                            current_size.rows,
                        )),
                    );
                    anyhow::ensure!(
                        outcome == InteractionOutcome::Continue,
                        "terminating keys cannot be replayed"
                    );
                }
            }
            if !plan.frames.contains(&target) {
                continue;
            }
            frame_index += 1;
            let frame = terminal
                .draw(|frame| {
                    ui::render(
                        frame,
                        &app,
                        interaction.active_mode,
                        interaction.peer_offset,
                        interaction.can_navigate,
                    )
                })
                .context("render capture frame")?;
            let elapsed = started_at.elapsed();
            let stem = FrameName {
                subject,
                scene,
                session: &session,
                native: false,
                index: frame_index,
                size: current_size,
                scheduled: target,
                actual: elapsed,
            }
            .stem();
            let artifacts = write_frame(&output_directory, &stem, frame.buffer)?;
            println!(
                "captured {} frame {} at {:.1}s (scheduled {:.1}s, {})\n  text {}\n  image {}",
                subject,
                frame_index,
                elapsed.as_secs_f64(),
                target.as_secs_f64(),
                current_size,
                artifacts.text.display(),
                artifacts.svg.display()
            );
        }
        Ok(())
    })();

    controls.send(MonitorControl::Stop).ok();
    monitor
        .join()
        .map_err(|_| anyhow::anyhow!("monitor thread panicked during capture"))?;
    result
}

pub fn run_native(request: CaptureRequest) -> Result<()> {
    let CaptureRequest {
        interval,
        mode,
        probe_policy,
        requested_seconds,
        size,
        output_directory,
        keys,
        resizes,
        scene,
    } = request;
    let plan = ReplayPlan::new(&requested_seconds, &keys, &resizes, scene)?;
    fs::create_dir_all(&output_directory)
        .with_context(|| format!("create capture directory {}", output_directory.display()))?;
    private_directory(&output_directory)?;

    let session_id = format!(
        "{}-{}",
        Local::now().format("%Y%m%dT%H%M%S"),
        std::process::id()
    );
    let subject = subject_name(mode);
    let server = format!("linktop-native-{}", std::process::id());
    let session = "capture";
    let binary = std::env::current_exe().context("locate current linktop executable")?;
    let working_directory = std::env::current_dir().context("read current directory")?;
    let final_seconds = plan.final_frame().as_secs();

    let _guard = TmuxGuard(server.clone());
    let interrupt = CaptureInterrupt::new().context("install native capture signal handlers")?;
    interrupt.check()?;
    let mut start = tmux_command(&server);
    configure_native_environment(&mut start, scene);
    start
        .args([
            "new-session",
            "-d",
            "-e",
            "COLORTERM=truecolor",
            "-s",
            session,
            "-x",
        ])
        .arg(size.columns.to_string())
        .arg("-y")
        .arg(size.rows.to_string())
        .arg("-c")
        .arg(&working_directory)
        .args(["env", "-u", "NO_COLOR", "COLORTERM=truecolor"])
        .arg(&binary);
    if probe_policy.is_active() {
        start.arg("--active");
    }
    match mode {
        MonitorMode::Overview => {}
        MonitorMode::Link => {
            start.arg("link");
        }
        MonitorMode::Peers => {
            start.arg("peers");
        }
    }
    start
        .args(["--interval"])
        .arg(interval.as_secs().to_string())
        .args(["--dwell"])
        .arg((final_seconds + 10).to_string());
    let output = process::run_bounded(&mut start, Duration::from_secs(5))
        .context("start native capture PTY")?
        .context("tmux did not start before its deadline")?;
    anyhow::ensure!(
        output.status.success(),
        "tmux failed to start native capture: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    interrupt.check()?;
    disable_native_status(&server, session)?;
    resize_native(&server, session, size)?;

    wait_for_native_ready(&server, session, size, NATIVE_READY_TIMEOUT, &interrupt)?;
    let started_at = Instant::now();
    let mut current_size = size;
    let mut frame_index = 0_usize;
    for target in plan.timestamps {
        wait_for_elapsed(target, started_at, &interrupt)?;
        let mut acted = false;
        if let Some(size) = plan.resizes.get(&target).copied() {
            resize_native(&server, session, size)?;
            current_size = size;
            acted = true;
        }
        if let Some(keys) = plan.keys.get(&target) {
            for key in keys {
                send_native_key(&server, session, key.tmux_key())?;
            }
            acted = true;
        }
        if acted {
            wait_for_native_ready(
                &server,
                session,
                current_size,
                NATIVE_READY_TIMEOUT,
                &interrupt,
            )?;
            thread::sleep(NATIVE_RENDER_SETTLE);
            interrupt.check()?;
        }
        if !plan.frames.contains(&target) {
            continue;
        }
        frame_index += 1;
        verify_native_size(&server, session, current_size)?;
        let elapsed = started_at.elapsed();
        let stem = FrameName {
            subject,
            scene,
            session: &session_id,
            native: true,
            index: frame_index,
            size: current_size,
            scheduled: target,
            actual: elapsed,
        }
        .stem();
        let artifacts = write_native_frame(
            &output_directory,
            &stem,
            &capture_pane(&server, session, false)?,
            &capture_pane(&server, session, true)?,
        )?;
        println!(
            "captured native {} frame {} at {:.1}s (scheduled {:.1}s, {})\n  text {}\n  ansi {}\n  html {}",
            subject,
            frame_index,
            elapsed.as_secs_f64(),
            target.as_secs_f64(),
            current_size,
            artifacts.text.display(),
            artifacts.ansi.display(),
            artifacts.html.display()
        );
    }
    Ok(())
}

fn resize_terminal(terminal: &mut Terminal<TestBackend>, size: CaptureSize) -> Result<()> {
    terminal.backend_mut().resize(size.columns, size.rows);
    terminal
        .resize(Rect::new(0, 0, size.columns, size.rows))
        .context("resize headless capture terminal")
}

fn wait_for_elapsed(
    target: Duration,
    started_at: Instant,
    interrupt: &CaptureInterrupt,
) -> Result<()> {
    loop {
        interrupt.check()?;
        let remaining = target.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Ok(());
        }
        thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

fn tmux_command(server: &str) -> Command {
    let mut command = Command::new("tmux");
    command.args(["-L", server, "-f", "/dev/null"]);
    command
}

fn configure_native_environment(command: &mut Command, scene: Option<CaptureScene>) {
    command.env_remove("LINKTOP_HISTORY");
    command.env_remove(SCREENSHOT_CHILD_SCENE);
    if let Some(scene) = scene {
        command.env(SCREENSHOT_CHILD_SCENE, scene.label());
    }
}

fn disable_native_status(server: &str, session: &str) -> Result<()> {
    let mut command = tmux_command(server);
    command.args(["set-option", "-t", session, "status", "off"]);
    run_tmux(&mut command, "disable native tmux status line")
}

fn resize_native(server: &str, session: &str, size: CaptureSize) -> Result<()> {
    let mut command = tmux_command(server);
    command
        .args(["resize-window", "-t", session, "-x"])
        .arg(size.columns.to_string())
        .arg("-y")
        .arg(size.rows.to_string());
    run_tmux(&mut command, "resize native capture window")
}

fn send_native_key(server: &str, session: &str, key: NativeKey<'_>) -> Result<()> {
    let mut command = tmux_command(server);
    command.args(["send-keys", "-t", session]);
    match key {
        NativeKey::Literal(value) => {
            command.arg("-l").arg(value);
        }
        NativeKey::Named(value) => {
            command.arg(value);
        }
    }
    run_tmux(&mut command, "send native capture key")
}

fn run_tmux(command: &mut Command, operation: &str) -> Result<()> {
    let output = process::run_bounded(command, Duration::from_secs(2))
        .with_context(|| operation.to_string())?
        .with_context(|| format!("{operation} did not finish before its deadline"))?;
    anyhow::ensure!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn native_size(server: &str, session: &str) -> Result<CaptureSize> {
    let mut command = tmux_command(server);
    command.args([
        "display-message",
        "-p",
        "-t",
        session,
        "#{pane_width}x#{pane_height}",
    ]);
    let output = process::run_bounded(&mut command, Duration::from_secs(2))
        .context("read native capture dimensions")?
        .context("tmux dimension query did not finish before its deadline")?;
    anyhow::ensure!(
        output.status.success(),
        "tmux could not report native capture dimensions: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let value = String::from_utf8(output.stdout).context("tmux dimensions were not UTF-8")?;
    let (columns, rows) = value
        .trim()
        .split_once('x')
        .context("tmux returned malformed capture dimensions")?;
    Ok(CaptureSize {
        columns: columns
            .parse()
            .context("tmux returned a malformed pane width")?,
        rows: rows
            .parse()
            .context("tmux returned a malformed pane height")?,
    })
}

fn verify_native_size(server: &str, session: &str, expected: CaptureSize) -> Result<()> {
    let actual = native_size(server, session)?;
    anyhow::ensure!(
        actual == expected,
        "native terminal is {actual}, expected {expected}"
    );
    Ok(())
}

fn wait_for_native_ready(
    server: &str,
    session: &str,
    expected_size: CaptureSize,
    timeout: Duration,
    interrupt: &CaptureInterrupt,
) -> Result<()> {
    let started_at = Instant::now();
    loop {
        interrupt.check()?;
        let size_ready = native_size(server, session).is_ok_and(|actual| actual == expected_size);
        let frame_ready =
            capture_pane_raw(server, session, false).is_ok_and(|frame| frame.contains("LINKTOP"));
        if size_ready && frame_ready {
            return Ok(());
        }
        anyhow::ensure!(
            started_at.elapsed() < timeout,
            "native Linktop view did not become ready at {expected_size} within {:.1}s",
            timeout.as_secs_f64()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

struct CaptureInterrupt {
    interrupted: Arc<AtomicBool>,
    registrations: Vec<signal_hook::SigId>,
}

impl CaptureInterrupt {
    fn new() -> Result<Self> {
        use signal_hook::consts::signal::{SIGINT, SIGTERM};

        let interrupted = Arc::new(AtomicBool::new(false));
        let registrations = [SIGINT, SIGTERM]
            .into_iter()
            .map(|signal| signal_hook::flag::register(signal, Arc::clone(&interrupted)))
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok(Self {
            interrupted,
            registrations,
        })
    }

    fn check(&self) -> Result<()> {
        anyhow::ensure!(
            !self.interrupted.load(Ordering::SeqCst),
            "native capture interrupted"
        );
        Ok(())
    }
}

impl Drop for CaptureInterrupt {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn capture_pane(server: &str, session: &str, styled: bool) -> Result<String> {
    let frame = capture_pane_raw(server, session, styled)?;
    anyhow::ensure!(
        frame.contains("LINKTOP"),
        "native terminal frame did not contain the Linktop view"
    );
    Ok(frame)
}

fn capture_pane_raw(server: &str, session: &str, styled: bool) -> Result<String> {
    let mut command = tmux_command(server);
    command.args(["capture-pane", "-p", "-N", "-t", session]);
    if styled {
        command.arg("-e");
    }
    let output = process::run_bounded(&mut command, Duration::from_secs(2))
        .context("capture native terminal pane")?
        .context("tmux capture did not finish before its deadline")?;
    anyhow::ensure!(
        output.status.success(),
        "tmux could not capture the native alternate screen: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let frame = String::from_utf8(output.stdout).context("native terminal frame was not UTF-8")?;
    Ok(frame)
}

struct TmuxGuard(String);

impl Drop for TmuxGuard {
    fn drop(&mut self) {
        let mut command = tmux_command(&self.0);
        command
            .arg("kill-server")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _ = process::run_bounded(&mut command, Duration::from_secs(2));
    }
}

pub(crate) fn child_scene_from_environment() -> Result<Option<CaptureScene>> {
    let Some(value) = std::env::var_os(SCREENSHOT_CHILD_SCENE) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{SCREENSHOT_CHILD_SCENE} is not valid UTF-8"))?;
    match value.as_str() {
        "dense-peers" => Ok(Some(CaptureScene::DensePeers)),
        _ => anyhow::bail!("{SCREENSHOT_CHILD_SCENE} has unsupported internal scene {value:?}"),
    }
}

pub(crate) fn start_scene_monitor() -> (
    Receiver<MonitorUpdate>,
    Sender<MonitorControl>,
    thread::JoinHandle<()>,
) {
    let (updates_tx, updates_rx) = mpsc::channel();
    let (controls_tx, controls_rx) = mpsc::channel();
    let monitor = thread::spawn(move || {
        let _updates_tx = updates_tx;
        while let Ok(control) = controls_rx.recv() {
            if matches!(control, MonitorControl::Stop) {
                break;
            }
        }
    });
    (updates_rx, controls_tx, monitor)
}

pub(crate) fn ensure_scene(app: &mut App, scene: CaptureScene) {
    match scene {
        CaptureScene::DensePeers => ensure_dense_peer_scene(app),
    }
}

fn ensure_dense_peer_scene(app: &mut App) {
    if app.link.gateway.as_deref() != Some(DENSE_SCENE_GATEWAY) {
        let generation = app.path_generation.saturating_add(1);
        app.apply(MonitorUpdate::Link {
            generation,
            snapshot: LinkSnapshot {
                host: "screenshot-fixture".into(),
                interface: Some("en-doc0".into()),
                link_type: Some("ethernet".into()),
                ssid: None,
                gateway: Some(DENSE_SCENE_GATEWAY.into()),
                resolvers: vec!["192.0.2.53".into(), "2001:db8::53".into()],
                addresses: vec![
                    Address {
                        interface: "en-doc0".into(),
                        address: "192.0.2.200".into(),
                        family: 4,
                        is_default: true,
                        is_temporary: false,
                    },
                    Address {
                        interface: "en-doc0".into(),
                        address: "2001:db8::200".into(),
                        family: 6,
                        is_default: true,
                        is_temporary: false,
                    },
                ],
                ..LinkSnapshot::empty()
            },
        });
    }
    if app.peers.detail == "27 synthetic cache entries; no liveness scan" {
        return;
    }

    let generation = app.path_generation;
    let baseline = dense_peer_baseline();
    app.apply(MonitorUpdate::Peers {
        generation,
        snapshot: PeerSnapshot {
            detail: "28 synthetic baseline cache entries; no liveness scan".into(),
            ..baseline.clone()
        },
    });

    let mut changed = baseline;
    if let Some(peer) = changed
        .peers
        .iter_mut()
        .find(|peer| peer.address == "192.0.2.3")
    {
        peer.mac = Some("02:00:00:ff:00:03".into());
    }
    if let Some(peer) = changed
        .peers
        .iter_mut()
        .find(|peer| peer.address == "192.0.2.4")
    {
        peer.mac = None;
        peer.binding_conflict = true;
        peer.mac_scope = None;
        peer.registrant = None;
    }
    if let Some(peer) = changed
        .peers
        .iter_mut()
        .find(|peer| peer.address == "192.0.2.5")
    {
        peer.state = Some("FAILED".into());
    }
    if let Some(peer) = changed
        .peers
        .iter_mut()
        .find(|peer| peer.address == "192.0.2.7")
    {
        peer.state = Some("PROBE".into());
    }
    changed
        .peers
        .retain(|peer| peer.address != "192.0.2.6" && peer.address != "2001:db8::a");
    changed.detail = "26 synthetic cache entries during transition; no liveness scan".into();
    app.apply(MonitorUpdate::Peers {
        generation,
        snapshot: changed.clone(),
    });

    let returned = dense_peer_baseline()
        .peers
        .into_iter()
        .find(|peer| peer.address == "192.0.2.6")
        .expect("dense scene includes return fixture");
    changed.peers.push(Peer {
        state: Some("REACHABLE".into()),
        ..returned
    });
    changed.detail = "27 synthetic cache entries; no liveness scan".into();
    app.apply(MonitorUpdate::Peers {
        generation,
        snapshot: changed,
    });
}

fn dense_peer_baseline() -> PeerSnapshot {
    let mut peers = Vec::with_capacity(28);
    for index in 1..=14_u8 {
        peers.push(synthetic_peer(
            format!("192.0.2.{index}"),
            index,
            if index == 1 { "REACHABLE" } else { "STALE" },
        ));
    }
    for index in 1..=14_u8 {
        peers.push(synthetic_peer(
            format!("2001:db8::{index:x}"),
            index.saturating_add(32),
            if index % 5 == 0 { "DELAY" } else { "STALE" },
        ));
    }
    if let Some(peer) = peers.iter_mut().find(|peer| peer.address == "192.0.2.8") {
        peer.mac = None;
        peer.mac_scope = None;
        peer.registrant = None;
    }
    PeerSnapshot {
        health: Health::Ok,
        detail: "28 synthetic baseline cache entries; no liveness scan".into(),
        sources: vec![
            "synthetic ARP cache fixture".into(),
            "synthetic NDP cache fixture".into(),
        ],
        failed_sources: Vec::new(),
        oui_source: Some("built-in synthetic QA scene".into()),
        peers,
    }
}

fn synthetic_peer(address: String, index: u8, state: &str) -> Peer {
    Peer {
        address,
        mac: Some(format!("02:00:00:00:00:{index:02x}")),
        interface: Some("en-doc0".into()),
        state: Some(state.into()),
        binding_conflict: false,
        mac_scope: Some(MacScope::Local),
        registrant: Some(if index == 1 {
            "Synthetic path gateway".into()
        } else {
            format!("Synthetic node {index:02}")
        }),
    }
}

fn wait_until(
    target: Duration,
    started_at: Instant,
    updates: &std::sync::mpsc::Receiver<crate::model::MonitorUpdate>,
    app: &mut App,
    mut history: Option<&mut history::HistorySession>,
) -> Result<()> {
    loop {
        let remaining = target.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Ok(());
        }
        match updates.recv_timeout(remaining.min(POLL_STEP)) {
            Ok(update) => {
                apply_monitor_update(app, history.as_deref_mut(), update);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("monitor stopped before the requested capture time");
            }
        }
    }
}

fn drain_updates(
    updates: &std::sync::mpsc::Receiver<crate::model::MonitorUpdate>,
    app: &mut App,
    mut history: Option<&mut history::HistorySession>,
) -> Result<()> {
    loop {
        match updates.try_recv() {
            Ok(update) => {
                apply_monitor_update(app, history.as_deref_mut(), update);
            }
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => {
                anyhow::bail!("monitor stopped before the frame was rendered");
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CaptureSchedule {
    targets: Vec<Duration>,
}

impl CaptureSchedule {
    fn new(seconds: &[u64]) -> Result<Self> {
        anyhow::ensure!(
            !seconds.is_empty(),
            "capture requires at least one --at time"
        );
        anyhow::ensure!(
            seconds.iter().all(|seconds| *seconds > 0),
            "capture times must be greater than zero"
        );
        let mut normalized = seconds.to_vec();
        normalized.sort_unstable();
        normalized.dedup();
        Ok(Self {
            targets: normalized.into_iter().map(Duration::from_secs).collect(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CaptureArtifacts {
    text: PathBuf,
    svg: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
struct NativeCaptureArtifacts {
    text: PathBuf,
    ansi: PathBuf,
    html: PathBuf,
}

fn write_frame(directory: &Path, stem: &str, buffer: &Buffer) -> Result<CaptureArtifacts> {
    let text = directory.join(format!("{stem}.txt"));
    let svg = directory.join(format!("{stem}.svg"));
    fs::write(&text, buffer_text(buffer))
        .with_context(|| format!("write text frame {}", text.display()))?;
    fs::write(&svg, buffer_svg(buffer))
        .with_context(|| format!("write SVG frame {}", svg.display()))?;
    private_file(&text)?;
    private_file(&svg)?;
    Ok(CaptureArtifacts { text, svg })
}

fn write_native_frame(
    directory: &Path,
    stem: &str,
    text_frame: &str,
    ansi_frame: &str,
) -> Result<NativeCaptureArtifacts> {
    let text = directory.join(format!("{stem}.txt"));
    let ansi = directory.join(format!("{stem}.ansi"));
    let html = directory.join(format!("{stem}.html"));
    let converted =
        ansi_to_html::convert(ansi_frame).context("convert native ANSI frame to HTML")?;
    let document = native_html_document(&converted);
    fs::write(&text, text_frame)
        .with_context(|| format!("write native text frame {}", text.display()))?;
    fs::write(&ansi, ansi_frame)
        .with_context(|| format!("write native ANSI frame {}", ansi.display()))?;
    fs::write(&html, document)
        .with_context(|| format!("write native HTML frame {}", html.display()))?;
    for path in [&text, &ansi, &html] {
        private_file(path)?;
    }
    Ok(NativeCaptureArtifacts { text, ansi, html })
}

fn native_html_document(frame: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Linktop native TUI capture</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: start;
  padding: 18px;
  background: #11161c;
  color: #c0cad6;
}}
pre {{
  margin: 0;
  font: 14px/18px monospace;
  white-space: pre;
  tab-size: 8;
}}
</style>
</head>
<body><pre>{frame}</pre></body>
</html>
"#
    )
}

fn buffer_text(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut output = String::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(cell) = buffer.cell((x, y)) {
                output.push_str(cell.symbol());
            }
        }
        output.push('\n');
    }
    output
}

fn buffer_svg(buffer: &Buffer) -> String {
    let area = buffer.area;
    let width = u32::from(area.width) * CELL_WIDTH + 2 * PADDING;
    let height = u32::from(area.height) * CELL_HEIGHT + 2 * PADDING;
    let mut output = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="{DEFAULT_BACKGROUND}"/>
<g font-family="monospace" font-size="14" xml:space="preserve">
"#
    );
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let Some(cell) = buffer.cell((x, y)) else {
                continue;
            };
            let reversed = cell.modifier.contains(Modifier::REVERSED);
            let (foreground, background) = if reversed {
                (color_hex(cell.bg, true), color_hex(cell.fg, false))
            } else {
                (color_hex(cell.fg, true), color_hex(cell.bg, false))
            };
            let draw_x = PADDING + u32::from(x - area.x) * CELL_WIDTH;
            let draw_y = PADDING + u32::from(y - area.y) * CELL_HEIGHT;
            if background != DEFAULT_BACKGROUND {
                output.push_str(&format!(
                    r#"<rect x="{draw_x}" y="{draw_y}" width="{CELL_WIDTH}" height="{CELL_HEIGHT}" fill="{background}"/>"#
                ));
                output.push('\n');
            }
            if cell.symbol().trim().is_empty() {
                continue;
            }
            let baseline = draw_y + CELL_HEIGHT - 4;
            let weight = if cell.modifier.contains(Modifier::BOLD) {
                "700"
            } else {
                "400"
            };
            let style = if cell.modifier.contains(Modifier::ITALIC) {
                "italic"
            } else {
                "normal"
            };
            let decoration = text_decoration(cell.modifier);
            output.push_str(&format!(
                r#"<text x="{draw_x}" y="{baseline}" fill="{foreground}" font-weight="{weight}" font-style="{style}" text-decoration="{decoration}">{}</text>"#,
                escape_xml(cell.symbol())
            ));
            output.push('\n');
        }
    }
    output.push_str("</g>\n</svg>\n");
    output
}

fn text_decoration(modifier: Modifier) -> &'static str {
    match (
        modifier.contains(Modifier::UNDERLINED),
        modifier.contains(Modifier::CROSSED_OUT),
    ) {
        (true, true) => "underline line-through",
        (true, false) => "underline",
        (false, true) => "line-through",
        (false, false) => "none",
    }
}

fn color_hex(color: Color, foreground: bool) -> String {
    match color {
        Color::Reset => if foreground {
            DEFAULT_FOREGROUND
        } else {
            DEFAULT_BACKGROUND
        }
        .into(),
        Color::Black => "#000000".into(),
        Color::Red => "#cd3131".into(),
        Color::Green => "#0dbc79".into(),
        Color::Yellow => "#e5e510".into(),
        Color::Blue => "#2472c8".into(),
        Color::Magenta => "#bc3fbc".into(),
        Color::Cyan => "#11a8cd".into(),
        Color::Gray => "#e5e5e5".into(),
        Color::DarkGray => "#666666".into(),
        Color::LightRed => "#f14c4c".into(),
        Color::LightGreen => "#23d18b".into(),
        Color::LightYellow => "#f5f543".into(),
        Color::LightBlue => "#3b8eea".into(),
        Color::LightMagenta => "#d670d6".into(),
        Color::LightCyan => "#29b8db".into(),
        Color::White => "#ffffff".into(),
        Color::Rgb(red, green, blue) => format!("#{red:02x}{green:02x}{blue:02x}"),
        Color::Indexed(index) => indexed_color(index),
    }
}

fn indexed_color(index: u8) -> String {
    const ANSI: [&str; 16] = [
        "#000000", "#800000", "#008000", "#808000", "#000080", "#800080", "#008080", "#c0c0c0",
        "#808080", "#ff0000", "#00ff00", "#ffff00", "#0000ff", "#ff00ff", "#00ffff", "#ffffff",
    ];
    if index < 16 {
        return ANSI[usize::from(index)].into();
    }
    if index >= 232 {
        let value = 8 + (index - 232) * 10;
        return format!("#{value:02x}{value:02x}{value:02x}");
    }
    let cube = index - 16;
    let levels = [0, 95, 135, 175, 215, 255];
    let red = levels[usize::from(cube / 36)];
    let green = levels[usize::from((cube % 36) / 6)];
    let blue = levels[usize::from(cube % 6)];
    format!("#{red:02x}{green:02x}{blue:02x}")
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn subject_name(mode: MonitorMode) -> &'static str {
    match mode {
        MonitorMode::Overview => "overview",
        MonitorMode::Link => "link",
        MonitorMode::Peers => "peers",
    }
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set private permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set private permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;

    use super::*;

    #[test]
    fn capture_schedule_sorts_and_deduplicates_times() {
        assert_eq!(
            CaptureSchedule::new(&[10, 2, 5, 2]).unwrap(),
            CaptureSchedule {
                targets: vec![
                    Duration::from_secs(2),
                    Duration::from_secs(5),
                    Duration::from_secs(10)
                ]
            }
        );
    }

    #[test]
    fn scheduled_actions_parse_expert_key_vocabulary_and_bounds() {
        assert_eq!(
            "5:page-down".parse::<ScheduledKey>().unwrap(),
            ScheduledKey {
                at: Duration::from_secs(5),
                key: ReplayKey::PageDown,
            }
        );
        assert_eq!(
            "3:80x20".parse::<ScheduledResize>().unwrap(),
            ScheduledResize {
                at: Duration::from_secs(3),
                size: CaptureSize {
                    columns: 80,
                    rows: 20,
                },
            }
        );
        assert!("0:j".parse::<ScheduledKey>().is_err());
        assert!("2:59x20".parse::<ScheduledResize>().is_err());
        assert!("2:80x9".parse::<ScheduledResize>().is_err());
        assert!("2:bogus".parse::<ScheduledKey>().is_err());
    }

    #[test]
    fn replay_plan_orders_resize_then_cli_ordered_keys_then_frame() {
        let keys = [
            "2:3".parse::<ScheduledKey>().unwrap(),
            "2:page-down".parse::<ScheduledKey>().unwrap(),
        ];
        let resizes = ["2:80x20".parse::<ScheduledResize>().unwrap()];
        let plan = ReplayPlan::new(&[5, 2, 5], &keys, &resizes, None).unwrap();
        assert_eq!(
            plan.timestamps,
            vec![Duration::from_secs(2), Duration::from_secs(5)]
        );
        assert_eq!(
            plan.resizes.get(&Duration::from_secs(2)),
            Some(&CaptureSize {
                columns: 80,
                rows: 20
            })
        );
        assert_eq!(
            plan.keys.get(&Duration::from_secs(2)).unwrap(),
            &[ReplayKey::Peers, ReplayKey::PageDown]
        );
        assert!(plan.frames.contains(&Duration::from_secs(2)));
    }

    #[test]
    fn replay_plan_rejects_conflicts_termination_and_actions_after_last_frame() {
        let conflicts = [
            "2:80x20".parse::<ScheduledResize>().unwrap(),
            "2:100x24".parse::<ScheduledResize>().unwrap(),
        ];
        assert!(ReplayPlan::new(&[5], &[], &conflicts, None).is_err());

        let terminating = ["2:q".parse::<ScheduledKey>().unwrap()];
        assert!(ReplayPlan::new(&[5], &terminating, &[], None).is_err());

        let late = ["6:j".parse::<ScheduledKey>().unwrap()];
        assert!(ReplayPlan::new(&[5], &late, &[], None).is_err());

        let active = ["2:a".parse::<ScheduledKey>().unwrap()];
        assert!(ReplayPlan::new(&[5], &active, &[], Some(CaptureScene::DensePeers)).is_err());
    }

    #[test]
    fn identical_same_time_resizes_are_deduplicated() {
        let resizes = [
            "2:80x20".parse::<ScheduledResize>().unwrap(),
            "2:80x20".parse::<ScheduledResize>().unwrap(),
        ];
        let plan = ReplayPlan::new(&[2], &[], &resizes, None).unwrap();
        assert_eq!(plan.resizes.len(), 1);
    }

    #[test]
    fn native_key_mapping_distinguishes_literal_and_named_tmux_keys() {
        assert_eq!(ReplayKey::Peers.tmux_key(), NativeKey::Literal("3"));
        assert_eq!(ReplayKey::Tab.tmux_key(), NativeKey::Named("Tab"));
        assert_eq!(ReplayKey::PageUp.tmux_key(), NativeKey::Named("PPage"));
        assert_eq!(ReplayKey::PageDown.tmux_key(), NativeKey::Named("NPage"));
    }

    #[test]
    fn native_child_environment_clears_host_history_and_stale_scene_defaults() {
        let mut command = Command::new("linktop");
        command.env("LINKTOP_HISTORY", "/private/host-history.jsonl");
        command.env(SCREENSHOT_CHILD_SCENE, "stale-scene");
        configure_native_environment(&mut command, Some(CaptureScene::DensePeers));

        let environment = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(ToOwned::to_owned)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.get(std::ffi::OsStr::new("LINKTOP_HISTORY")),
            Some(&None)
        );
        assert_eq!(
            environment
                .get(std::ffi::OsStr::new(SCREENSHOT_CHILD_SCENE))
                .and_then(|value| value.as_deref()),
            Some(std::ffi::OsStr::new("dense-peers"))
        );
    }

    #[test]
    fn headless_terminal_resize_changes_the_rendered_viewport() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        resize_terminal(
            &mut terminal,
            CaptureSize {
                columns: 80,
                rows: 20,
            },
        )
        .unwrap();
        let frame = terminal
            .draw(|frame| {
                frame.render_widget(ratatui::widgets::Paragraph::new("resized"), frame.area());
            })
            .unwrap();
        assert_eq!(frame.buffer.area, Rect::new(0, 0, 80, 20));
    }

    #[test]
    fn dense_scene_exercises_attention_dwell_and_overflow_with_synthetic_evidence() {
        let mut app = App::with_probe_policy(ProbePolicy::Passive);
        ensure_scene(&mut app, CaptureScene::DensePeers);
        let summary = app.peer_dwell_summary();
        assert_eq!(app.link.gateway.as_deref(), Some(DENSE_SCENE_GATEWAY));
        assert_eq!(summary.current, 27);
        assert_eq!(summary.observed, 28);
        assert!(summary.changed >= 4);
        assert_eq!(summary.disappeared, 1);

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| ui::render(frame, &app, MonitorMode::Peers, 0, false))
            .unwrap();
        let rendered = buffer_text(terminal.backend().buffer());
        assert!(rendered.contains("/ 27 / NO SCAN"));
        assert!(rendered.contains("source disagreement"));
        assert!(rendered.contains("binding changed"));
        assert!(rendered.contains("Synthetic"));
        assert!(rendered.contains("en-doc0 192.0.2."));
    }

    #[test]
    fn synthetic_scene_monitor_collects_no_host_updates_and_stops_cleanly() {
        let (updates, controls, monitor) = start_scene_monitor();
        assert!(matches!(
            updates.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        controls.send(MonitorControl::Refresh).unwrap();
        assert!(matches!(
            updates.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        controls.send(MonitorControl::Stop).unwrap();
        monitor.join().unwrap();
    }

    #[test]
    fn styled_svg_preserves_cell_color_and_escapes_text() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 2, 1));
        buffer[(0, 0)]
            .set_symbol("<")
            .set_fg(Color::Rgb(37, 203, 216))
            .set_bg(Color::Rgb(17, 22, 28))
            .set_style(ratatui::style::Style::default().add_modifier(Modifier::BOLD));
        let svg = buffer_svg(&buffer);
        assert!(svg.contains(r##"fill="#25cbd8""##));
        assert!(svg.contains("font-weight=\"700\""));
        assert!(svg.contains("&lt;"));
    }

    #[test]
    fn text_frame_keeps_fixed_dimensions() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 3, 2));
        buffer[(0, 0)].set_symbol("A");
        buffer[(2, 1)].set_symbol("Z");
        assert_eq!(buffer_text(&buffer), "A  \n  Z\n");
    }

    #[test]
    fn native_html_wraps_converted_ansi_as_a_fixed_terminal_frame() {
        let html = native_html_document("<span style='color:#0f0'>OK</span>");
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("white-space: pre"));
        assert!(html.contains("<span style='color:#0f0'>OK</span>"));
    }
}
