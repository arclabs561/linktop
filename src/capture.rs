use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{Local, SecondsFormat, Utc};
use clap::ValueEnum;
use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};
use serde::Serialize;
use sha2::{Digest, Sha256};

use netbraid_replay::{
    HostPathObservationV0, NetworkNameVisibilityV0, ScenarioPrivacyV0, builtin_scenario_v0,
    replay_scenario_v0,
};

use crate::model::{
    Address, App, Health, LinkSnapshot, MacScope, MonitorControl, MonitorMode, MonitorUpdate,
    NetworkConfiguration, Peer, PeerSnapshot, ProbePolicy,
};
use crate::{
    InteractionOutcome, InteractionState, apply_monitor_update, apply_tui_key, history, net,
    process, ui,
};

const POLL_STEP: Duration = Duration::from_millis(100);
const NATIVE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_RENDER_SETTLE: Duration = Duration::from_millis(200);
const SCREENSHOT_CHILD_SCENE: &str = "LINKTOP_SCREENSHOT_CHILD_SCENE";
const SCREENSHOT_CHILD_SCENE_GATE: &str = "LINKTOP_SCREENSHOT_CHILD_SCENE_GATE";
const QA_MANIFEST_SCHEMA: &str = "linktop.qa_capture_manifest.v1";
static QA_PREFLIGHT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const DENSE_SCENE_GATEWAY: &str = "192.0.2.1";
const DEFAULT_BACKGROUND: &str = "#11161c";
const DEFAULT_FOREGROUND: &str = "#c0cad6";
const CELL_WIDTH: u32 = 9;
const CELL_HEIGHT: u32 = 18;
const PADDING: u32 = 18;
const WIFI_SCENE_TIMELINE: [(Duration, &str); 3] = [
    (Duration::ZERO, "wifi-initial"),
    (Duration::from_secs(2), "hotspot-attached"),
    (Duration::from_secs(4), "wifi-returned"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    WifiHotspotWifi,
}

impl CaptureScene {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::DensePeers => "dense-peers",
            Self::WifiHotspotWifi => "wifi-hotspot-wifi",
        }
    }

    fn stage_at(self, elapsed: Duration) -> &'static str {
        match self {
            Self::DensePeers => "final",
            Self::WifiHotspotWifi if elapsed < Duration::from_secs(2) => "wifi-initial",
            Self::WifiHotspotWifi if elapsed < Duration::from_secs(4) => "hotspot-attached",
            Self::WifiHotspotWifi => "wifi-returned",
        }
    }

    fn timeline(self) -> &'static [(Duration, &'static str)] {
        match self {
            Self::DensePeers => &[],
            Self::WifiHotspotWifi => &WIFI_SCENE_TIMELINE,
        }
    }

    fn transition_times(self) -> impl Iterator<Item = Duration> {
        self.timeline().iter().skip(1).map(|(elapsed, _)| *elapsed)
    }

    fn is_timed(self) -> bool {
        !self.timeline().is_empty()
    }

    pub(crate) fn supports(self, mode: MonitorMode) -> bool {
        match self {
            Self::DensePeers => matches!(mode, MonitorMode::Overview | MonitorMode::Peers),
            Self::WifiHotspotWifi => mode == MonitorMode::Overview,
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
    fn label(self) -> &'static str {
        match self {
            Self::Refresh => "r",
            Self::Pause => "p",
            Self::Active => "a",
            Self::Overview => "1",
            Self::Link => "2",
            Self::Peers => "3",
            Self::Tab => "tab",
            Self::Down => "down",
            Self::Up => "up",
            Self::PageDown => "page-down",
            Self::PageUp => "page-up",
            Self::Home => "home",
            Self::End => "end",
            Self::Quit => "q",
            Self::Escape => "esc",
        }
    }

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
        let columns = parse_u16_bound(columns, "columns", 40, 300)?;
        let rows = parse_u16_bound(rows, "rows", 8, 100)?;
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
    scene_stages: Vec<QaSceneStage>,
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
                "synthetic scenes cannot replay `a` because they are passive"
            );
            anyhow::ensure!(
                !(scene.is_some_and(CaptureScene::is_timed) && scheduled.key == ReplayKey::Pause),
                "timed synthetic scenes cannot replay `p` because their QA clock is not operator-paused"
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
        let scene_stages = scene
            .into_iter()
            .flat_map(CaptureScene::timeline)
            .filter(|(elapsed, _)| *elapsed <= final_frame)
            .map(|(elapsed, stage)| QaSceneStage {
                at_ms: duration_millis(*elapsed),
                stage,
            })
            .collect::<Vec<_>>();
        let scene_transitions = scene
            .into_iter()
            .flat_map(CaptureScene::transition_times)
            .filter(|elapsed| *elapsed <= final_frame);
        let timestamps = frames
            .iter()
            .chain(scheduled_keys.keys())
            .chain(scheduled_resizes.keys())
            .copied()
            .chain(scene_transitions)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Self {
            frames,
            keys: scheduled_keys,
            resizes: scheduled_resizes,
            scene_stages,
            timestamps,
        })
    }

    fn final_frame(&self) -> Duration {
        *self
            .frames
            .last()
            .expect("validated replay plan is nonempty")
    }

    fn manifest_replay(&self) -> QaReplay {
        let frames_ms = self
            .frames
            .iter()
            .map(|duration| duration_millis(*duration))
            .collect();
        let keys = self
            .keys
            .iter()
            .flat_map(|(at, keys)| {
                keys.iter().map(|key| QaKeyAction {
                    at_ms: duration_millis(*at),
                    key: key.label(),
                })
            })
            .collect();
        let resizes = self
            .resizes
            .iter()
            .map(|(at, viewport)| QaResizeAction {
                at_ms: duration_millis(*at),
                viewport: *viewport,
            })
            .collect();
        QaReplay {
            frames_ms,
            keys,
            resizes,
            scene_stages: self.scene_stages.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeKey<'a> {
    Literal(&'a str),
    Named(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaProducer {
    name: &'static str,
    version: &'static str,
    executable_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaReplay {
    frames_ms: Vec<u64>,
    keys: Vec<QaKeyAction>,
    resizes: Vec<QaResizeAction>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scene_stages: Vec<QaSceneStage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaKeyAction {
    at_ms: u64,
    key: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaResizeAction {
    at_ms: u64,
    viewport: CaptureSize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaSceneStage {
    at_ms: u64,
    stage: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaCaptureManifest {
    schema: &'static str,
    transaction_id: String,
    started_at: String,
    completed_at: String,
    duration_ms: u64,
    producer: QaProducer,
    lane: &'static str,
    requested_subject: &'static str,
    scene: &'static str,
    initial_policy: &'static str,
    replay: QaReplay,
    frames: Vec<QaFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QaManifestMetadata {
    transaction_id: String,
    started_at: String,
    completed_at: String,
    duration_ms: u64,
    native: bool,
    requested_mode: MonitorMode,
    probe_policy: ProbePolicy,
    scene: Option<CaptureScene>,
    executable_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaFrame {
    index: usize,
    rendered_view: &'static str,
    scene: &'static str,
    stage: &'static str,
    policy: &'static str,
    scheduled_ms: u64,
    actual_ms: u64,
    viewport: CaptureSize,
    artifacts: Vec<QaArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QaFrameMetadata {
    index: usize,
    rendered_mode: MonitorMode,
    probe_policy: ProbePolicy,
    scene: Option<CaptureScene>,
    scheduled: Duration,
    actual: Duration,
    viewport: CaptureSize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QaArtifact {
    name: String,
    media_type: &'static str,
    byte_length: u64,
    sha256: String,
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

fn manifest_stem(
    requested_subject: &str,
    scene: Option<CaptureScene>,
    session: &str,
    native: bool,
) -> String {
    format!(
        "{}-{}-{}{}-qa-capture-manifest-v1",
        requested_subject,
        scene.map_or("live", CaptureScene::label),
        session,
        if native { "-native" } else { "" },
    )
}

fn qa_manifest(
    metadata: QaManifestMetadata,
    replay: QaReplay,
    frames: Vec<QaFrame>,
) -> QaCaptureManifest {
    let QaManifestMetadata {
        transaction_id,
        started_at,
        completed_at,
        duration_ms,
        native,
        requested_mode,
        probe_policy,
        scene,
        executable_sha256,
    } = metadata;
    QaCaptureManifest {
        schema: QA_MANIFEST_SCHEMA,
        transaction_id,
        started_at,
        completed_at,
        duration_ms,
        producer: QaProducer {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            executable_sha256,
        },
        lane: if native { "native" } else { "deterministic" },
        requested_subject: subject_name(requested_mode),
        scene: scene.map_or("live", CaptureScene::label),
        initial_policy: policy_name(probe_policy),
        replay,
        frames,
    }
}

fn current_executable_sha256() -> Result<String> {
    let executable = std::env::current_exe().context("locate current Linktop executable")?;
    let bytes = fs::read(&executable)
        .with_context(|| format!("read current Linktop executable {}", executable.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn policy_name(policy: ProbePolicy) -> &'static str {
    if policy.is_active() {
        "active"
    } else {
        "passive"
    }
}

fn utc_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn qa_frame(metadata: QaFrameMetadata, artifacts: Vec<QaArtifact>) -> QaFrame {
    QaFrame {
        index: metadata.index,
        rendered_view: subject_name(metadata.rendered_mode),
        scene: metadata.scene.map_or("live", CaptureScene::label),
        stage: metadata
            .scene
            .map_or("observed", |scene| scene.stage_at(metadata.scheduled)),
        policy: policy_name(metadata.probe_policy),
        scheduled_ms: duration_millis(metadata.scheduled),
        actual_ms: duration_millis(metadata.actual),
        viewport: metadata.viewport,
        artifacts,
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
    let replay = plan.manifest_replay();
    let executable_sha256 = current_executable_sha256()?;
    fs::create_dir_all(&output_directory)
        .with_context(|| format!("create capture directory {}", output_directory.display()))?;
    private_directory(&output_directory)?;
    verify_manifest_publication_support(&output_directory)?;

    let session = format!(
        "{}-{}",
        Local::now().format("%Y%m%dT%H%M%S"),
        std::process::id()
    );
    let requested_subject = subject_name(mode);
    let manifest_stem = manifest_stem(requested_subject, scene, &session, false);
    let backend = TestBackend::new(size.columns, size.rows);
    let mut terminal = Terminal::new(backend).context("create capture terminal")?;
    let (updates, controls, monitor) = if scene.is_some() {
        start_scene_monitor()
    } else {
        net::start_monitor(interval, mode, probe_policy)
    };
    let replay_started_at = utc_timestamp();
    let started_at = Instant::now();
    let mut app = App::with_probe_policy(probe_policy);
    let mut scene_runtime = scene
        .map(|scene| SceneRuntime::new(scene, None))
        .transpose()?;
    if let Some(runtime) = scene_runtime.as_mut() {
        runtime.advance_to(&mut app, Duration::ZERO)?;
    }
    let mut interaction = InteractionState {
        active_mode: mode,
        peer_offset: 0,
        peer_selection: None,
        can_navigate: mode == MonitorMode::Overview,
    };
    let mut current_size = size;
    let mut frame_index = 0_usize;
    let result = (|| -> Result<Vec<QaFrame>> {
        let mut manifest_frames = Vec::with_capacity(plan.frames.len());
        for target in plan.timestamps.iter().copied() {
            wait_until(target, started_at, &updates, &mut app, None)?;
            drain_updates(&updates, &mut app, None)?;
            if let Some(runtime) = scene_runtime.as_mut() {
                runtime.advance_to(&mut app, target)?;
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
            interaction.normalize_peer_selection(&app);
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
            let rendered_mode = interaction.active_mode;
            let rendered_view = subject_name(rendered_mode);
            let stem = FrameName {
                subject: rendered_view,
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
            manifest_frames.push(qa_frame(
                QaFrameMetadata {
                    index: frame_index,
                    rendered_mode,
                    probe_policy: app.probe_policy(),
                    scene,
                    scheduled: target,
                    actual: elapsed,
                    viewport: current_size,
                },
                artifacts.manifest_records(&output_directory)?,
            ));
            println!(
                "captured {} frame {} at {:.1}s (scheduled {:.1}s, {})\n  text {}\n  image {}",
                rendered_view,
                frame_index,
                elapsed.as_secs_f64(),
                target.as_secs_f64(),
                current_size,
                artifacts.text.display(),
                artifacts.svg.display()
            );
        }
        Ok(manifest_frames)
    })();

    let replay_duration_ms = duration_millis(started_at.elapsed());
    let replay_completed_at = utc_timestamp();
    controls.send(MonitorControl::Stop).ok();
    monitor
        .join()
        .map_err(|_| anyhow::anyhow!("monitor thread panicked during capture"))?;
    let frames = result?;
    let manifest = qa_manifest(
        QaManifestMetadata {
            transaction_id: session,
            started_at: replay_started_at,
            completed_at: replay_completed_at,
            duration_ms: replay_duration_ms,
            native: false,
            requested_mode: mode,
            probe_policy,
            scene,
            executable_sha256,
        },
        replay,
        frames,
    );
    let manifest_path = write_manifest(&output_directory, &manifest_stem, &manifest)?;
    println!("  manifest {}", manifest_path.display());
    Ok(())
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
    let replay = plan.manifest_replay();
    let executable_sha256 = current_executable_sha256()?;
    fs::create_dir_all(&output_directory)
        .with_context(|| format!("create capture directory {}", output_directory.display()))?;
    private_directory(&output_directory)?;
    verify_manifest_publication_support(&output_directory)?;

    let session_id = format!(
        "{}-{}",
        Local::now().format("%Y%m%dT%H%M%S"),
        std::process::id()
    );
    let requested_subject = subject_name(mode);
    let server = format!("linktop-native-{}", std::process::id());
    let session = "capture";
    let binary = std::env::current_exe().context("locate current linktop executable")?;
    let working_directory = std::env::current_dir().context("read current directory")?;
    let final_seconds = plan.final_frame().as_secs();
    let manifest_stem = manifest_stem(requested_subject, scene, &session_id, true);
    let mut scene_gate = scene
        .filter(|scene| scene.is_timed())
        .map(|_| SceneGate::new(&output_directory, &manifest_stem))
        .transpose()?;

    let _guard = TmuxGuard(server.clone());
    let interrupt = CaptureInterrupt::new().context("install native capture signal handlers")?;
    interrupt.check()?;
    let mut start = tmux_command(&server);
    configure_native_environment(&mut start, scene, scene_gate.as_ref().map(SceneGate::path));
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
    if scene.is_some() {
        start.arg("--internal-screenshot-child");
    }
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
    let replay_started_at = utc_timestamp();
    let started_at = Instant::now();
    if let Some(gate) = scene_gate.as_mut() {
        gate.open()?;
    }
    let mut current_size = size;
    let mut frame_index = 0_usize;
    let mut projected_app = App::with_probe_policy(probe_policy);
    let mut projected_interaction = InteractionState {
        active_mode: mode,
        peer_offset: 0,
        peer_selection: None,
        can_navigate: mode == MonitorMode::Overview,
    };
    let native_scene_runtime = scene
        .map(|scene| SceneRuntime::new(scene, None))
        .transpose()?;
    let (projected_controls, _projected_controls_rx) = mpsc::channel();
    let mut manifest_frames = Vec::with_capacity(plan.frames.len());
    for target in plan.timestamps.iter().copied() {
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
                let outcome = apply_tui_key(
                    &mut projected_app,
                    &projected_controls,
                    &mut projected_interaction,
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
        if let Some(expectation) = native_scene_runtime
            .as_ref()
            .and_then(|runtime| runtime.native_expectation_at(target))
        {
            wait_for_native_scene_stage(
                &server,
                session,
                &expectation,
                NATIVE_READY_TIMEOUT,
                &interrupt,
            )?;
        }
        verify_native_size(&server, session, current_size)?;
        let elapsed = started_at.elapsed();
        let rendered_mode = projected_interaction.active_mode;
        let rendered_view = subject_name(rendered_mode);
        let stem = FrameName {
            subject: rendered_view,
            scene,
            session: &session_id,
            native: true,
            index: frame_index,
            size: current_size,
            scheduled: target,
            actual: elapsed,
        }
        .stem();
        let ansi_frame = capture_pane(&server, session, true)?;
        let text_frame = strip_ansi_escapes::strip_str(&ansi_frame);
        verify_captured_state(&text_frame, rendered_mode, projected_app.probe_policy())?;
        let artifacts = write_native_frame(&output_directory, &stem, &text_frame, &ansi_frame)?;
        manifest_frames.push(qa_frame(
            QaFrameMetadata {
                index: frame_index,
                rendered_mode,
                probe_policy: projected_app.probe_policy(),
                scene,
                scheduled: target,
                actual: elapsed,
                viewport: current_size,
            },
            artifacts.manifest_records(&output_directory)?,
        ));
        println!(
            "captured native {} frame {} at {:.1}s (scheduled {:.1}s, {})\n  text {}\n  ansi {}\n  html {}",
            rendered_view,
            frame_index,
            elapsed.as_secs_f64(),
            target.as_secs_f64(),
            current_size,
            artifacts.text.display(),
            artifacts.ansi.display(),
            artifacts.html.display()
        );
    }
    let replay_duration_ms = duration_millis(started_at.elapsed());
    let replay_completed_at = utc_timestamp();
    let manifest = qa_manifest(
        QaManifestMetadata {
            transaction_id: session_id,
            started_at: replay_started_at,
            completed_at: replay_completed_at,
            duration_ms: replay_duration_ms,
            native: true,
            requested_mode: mode,
            probe_policy,
            scene,
            executable_sha256,
        },
        replay,
        manifest_frames,
    );
    let manifest_path = write_manifest(&output_directory, &manifest_stem, &manifest)?;
    println!("  manifest {}", manifest_path.display());
    Ok(())
}

fn verify_captured_state(frame: &str, mode: MonitorMode, policy: ProbePolicy) -> Result<()> {
    let header = frame.lines().take(3).collect::<Vec<_>>().join("\n");
    let footer = frame.lines().next_back().unwrap_or_default();
    let matches = match mode {
        MonitorMode::Overview => {
            header.contains("OVERVIEW")
                || header.contains("NETWORK CONTEXT")
                || header.contains("PATH DIAGNOSIS / ACTIVE")
        }
        MonitorMode::Link => header.contains("LOCAL LINK"),
        MonitorMode::Peers => header.contains("NEIGHBORS") || header.contains("NEIGHBOR CACHE"),
    };
    anyhow::ensure!(
        matches,
        "native terminal frame did not render the expected {} view",
        subject_name(mode)
    );
    let visible_policy = |text: &str| {
        if text.contains("PATH DIAGNOSIS / ACTIVE")
            || text.contains("LOCAL LINK / ACTIVE")
            || text.contains("NEIGHBOR CACHE / ACTIVE")
            || text.contains("NEIGHBORS / ACTIVE")
            || text.contains("probes:on")
            || text.contains("· ACTIVE ·")
        {
            Some(ProbePolicy::Active)
        } else if text.contains("PASSIVE")
            || text.contains("probes:off")
            || text.contains("· PASSIVE ·")
        {
            Some(ProbePolicy::Passive)
        } else {
            None
        }
    };
    let observed_policy = visible_policy(&header).or_else(|| visible_policy(footer));
    anyhow::ensure!(
        observed_policy == Some(policy),
        "native terminal frame did not render the expected {} policy",
        policy_name(policy)
    );
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

fn configure_native_environment(
    command: &mut Command,
    scene: Option<CaptureScene>,
    scene_gate: Option<&Path>,
) {
    command.env_remove("LINKTOP_HISTORY");
    command.env_remove(SCREENSHOT_CHILD_SCENE);
    command.env_remove(SCREENSHOT_CHILD_SCENE_GATE);
    if let Some(scene) = scene {
        command.env(SCREENSHOT_CHILD_SCENE, scene.label());
    }
    if let Some(scene_gate) = scene_gate {
        command.env(SCREENSHOT_CHILD_SCENE_GATE, scene_gate);
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

fn wait_for_native_scene_stage(
    server: &str,
    session: &str,
    expectation: &NativeSceneExpectation,
    timeout: Duration,
    interrupt: &CaptureInterrupt,
) -> Result<()> {
    let started_at = Instant::now();
    loop {
        interrupt.check()?;
        let ready = capture_pane_raw(server, session, false)
            .is_ok_and(|frame| native_scene_stage_visible(&frame, expectation));
        if ready {
            return Ok(());
        }
        anyhow::ensure!(
            started_at.elapsed() < timeout,
            "native scene {} did not render stage {} within {:.1}s",
            expectation.scene.label(),
            expectation.stage,
            timeout.as_secs_f64()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn native_scene_stage_visible(frame: &str, expectation: &NativeSceneExpectation) -> bool {
    let generation = format!("GEN {}", expectation.generation);
    frame.contains(&generation)
        && (frame.contains("resize to inspect evidence")
            || frame.contains(&expectation.path_marker))
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

struct SceneGate {
    path: PathBuf,
    opened: bool,
}

impl SceneGate {
    fn new(output_directory: &Path, manifest_stem: &str) -> Result<Self> {
        let path = output_directory.join(format!(".{manifest_stem}.scene-start"));
        anyhow::ensure!(
            !path.exists(),
            "native scene start gate already exists: {}",
            path.display()
        );
        Ok(Self {
            path,
            opened: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn open(&mut self) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
            .with_context(|| format!("create native scene start gate {}", self.path.display()))?;
        self.opened = true;
        private_file(&self.path)?;
        file.write_all(b"start\n")
            .with_context(|| format!("write native scene start gate {}", self.path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync native scene start gate {}", self.path.display()))?;
        Ok(())
    }
}

impl Drop for SceneGate {
    fn drop(&mut self) {
        if self.opened {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn child_scene_from_environment(authorized: bool) -> Result<Option<SceneRuntime>> {
    if !authorized {
        return Ok(None);
    }
    child_scene_from_values(
        std::env::var_os(SCREENSHOT_CHILD_SCENE),
        std::env::var_os(SCREENSHOT_CHILD_SCENE_GATE).map(PathBuf::from),
    )
}

fn child_scene_from_values(
    value: Option<OsString>,
    gate: Option<PathBuf>,
) -> Result<Option<SceneRuntime>> {
    let Some(value) = value else {
        anyhow::bail!("{SCREENSHOT_CHILD_SCENE} is required for an internal screenshot child");
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{SCREENSHOT_CHILD_SCENE} is not valid UTF-8"))?;
    let scene = match value.as_str() {
        "dense-peers" => CaptureScene::DensePeers,
        "wifi-hotspot-wifi" => CaptureScene::WifiHotspotWifi,
        _ => anyhow::bail!("{SCREENSHOT_CHILD_SCENE} has unsupported internal scene {value:?}"),
    };
    anyhow::ensure!(
        !scene.is_timed() || gate.is_some(),
        "{SCREENSHOT_CHILD_SCENE_GATE} is required for timed internal scene {}",
        scene.label()
    );
    SceneRuntime::new(scene, gate).map(Some)
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

#[cfg(test)]
pub(crate) fn ensure_scene(app: &mut App, scene: CaptureScene) {
    match scene {
        CaptureScene::DensePeers => ensure_dense_peer_scene(app),
        CaptureScene::WifiHotspotWifi => {
            let mut runtime =
                SceneRuntime::new(scene, None).expect("built-in public scenario is valid");
            runtime
                .advance_to(app, Duration::ZERO)
                .expect("apply built-in public scenario");
        }
    }
}

#[derive(Debug, Clone)]
struct SceneStage {
    at: Duration,
    records: Vec<HostPathObservationV0>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeSceneExpectation {
    scene: CaptureScene,
    stage: &'static str,
    generation: u64,
    path_marker: String,
}

pub(crate) struct SceneRuntime {
    scene: CaptureScene,
    stages: Vec<SceneStage>,
    applied_stages: usize,
    gate: Option<PathBuf>,
    started_at: Option<Instant>,
}

impl SceneRuntime {
    fn new(scene: CaptureScene, gate: Option<PathBuf>) -> Result<Self> {
        let stages = match scene {
            CaptureScene::DensePeers => Vec::new(),
            CaptureScene::WifiHotspotWifi => wifi_hotspot_wifi_stages()?,
        };
        Ok(Self {
            scene,
            stages,
            applied_stages: 0,
            gate,
            started_at: None,
        })
    }

    pub(crate) fn poll(&mut self, app: &mut App) -> Result<()> {
        self.advance_to(app, Duration::ZERO)?;
        let Some(gate) = self.gate.as_deref() else {
            return Ok(());
        };
        if self.started_at.is_none() && scene_gate_is_open(gate)? {
            self.started_at = Some(Instant::now());
        }
        if let Some(started_at) = self.started_at {
            self.advance_to(app, started_at.elapsed())?;
        }
        Ok(())
    }

    fn advance_to(&mut self, app: &mut App, elapsed: Duration) -> Result<()> {
        if self.scene == CaptureScene::DensePeers {
            ensure_dense_peer_scene(app);
            return Ok(());
        }
        while let Some(stage) = self.stages.get(self.applied_stages) {
            if stage.at > elapsed {
                break;
            }
            apply_host_path_stage(app, &stage.records)?;
            self.applied_stages += 1;
        }
        Ok(())
    }

    fn native_expectation_at(&self, elapsed: Duration) -> Option<NativeSceneExpectation> {
        let (index, stage) = self
            .stages
            .iter()
            .enumerate()
            .rev()
            .find(|(_, stage)| stage.at <= elapsed)?;
        let current = stage.records.last()?;
        let path_marker = current
            .path
            .network_name
            .value
            .clone()
            .or_else(|| current.path.next_hop.clone())
            .or_else(|| current.path.interface.clone())?;
        Some(NativeSceneExpectation {
            scene: self.scene,
            stage: self.scene.stage_at(elapsed),
            generation: (index + 1) as u64,
            path_marker,
        })
    }
}

fn wifi_hotspot_wifi_stages() -> Result<Vec<SceneStage>> {
    let bundle =
        builtin_scenario_v0("wifi-hotspot-wifi").context("load built-in Wi-Fi transition scene")?;
    anyhow::ensure!(
        bundle.manifest().privacy == ScenarioPrivacyV0::PublicSynthetic,
        "Wi-Fi transition scene must be PUBLIC_SYNTHETIC"
    );
    [
        (Duration::ZERO, "wifi-initial"),
        (Duration::from_secs(2), "hotspot-attached"),
        (Duration::from_secs(4), "wifi-returned"),
    ]
    .into_iter()
    .map(|(at, checkpoint)| {
        let receipt = replay_scenario_v0(&bundle, checkpoint)
            .with_context(|| format!("replay Wi-Fi transition checkpoint {checkpoint}"))?;
        let inputs = bundle
            .checkpoint_inputs_v0(&receipt)
            .with_context(|| format!("resolve Wi-Fi transition checkpoint {checkpoint}"))?;
        anyhow::ensure!(
            !inputs.host_path_records.is_empty(),
            "Wi-Fi transition checkpoint {checkpoint} has no host-path evidence"
        );
        anyhow::ensure!(
            inputs.saved_capture_streams.is_empty(),
            "Wi-Fi transition checkpoint {checkpoint} unexpectedly contains packet evidence"
        );
        Ok(SceneStage {
            at,
            records: inputs.host_path_records,
        })
    })
    .collect()
}

fn apply_host_path_stage(app: &mut App, records: &[HostPathObservationV0]) -> Result<()> {
    let current = records
        .last()
        .context("synthetic scene stage has no current host-path record")?;
    let generation = app.path_generation.saturating_add(1);
    let network_configuration = (current.path.association_id.is_some()
        || current.path.associated_bssid.is_some())
    .then(|| {
        Box::new(NetworkConfiguration {
            connection_id: current.path.association_id.clone(),
            associated_bssid: current.path.associated_bssid.clone(),
            bssid_restricted: false,
            method: None,
            state: None,
            server: None,
            subnet_mask: None,
            lease_seconds: None,
            lease_started_at: None,
            lease_expires_at: None,
            router_arp_verified: None,
            security: None,
        })
    });
    let accepted = app.apply(MonitorUpdate::Link {
        generation,
        snapshot: LinkSnapshot {
            host: current.source.observer_id.clone(),
            interface: current.path.interface.clone(),
            link_type: current.path.link_type.clone(),
            underlay: None,
            ssid: current.path.network_name.value.clone(),
            ssid_restricted: current.path.network_name.visibility
                == NetworkNameVisibilityV0::Restricted,
            wifi: None,
            gateway: current.path.next_hop.clone(),
            public_ip: None,
            resolvers: current.path.resolvers.clone(),
            // Network prefixes cannot reconstruct a host address, role, or
            // temporary-address lifetime.
            addresses: Vec::new(),
            network_configuration,
        },
    });
    anyhow::ensure!(accepted, "synthetic host-path generation was rejected");
    app.history_context = Some(history::summarize(
        &records[..records.len().saturating_sub(1)],
        current,
    ));
    Ok(())
}

fn scene_gate_is_open(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "native scene start gate is not a regular file"
            );
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("inspect native scene start gate {}", path.display())),
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
        path_filter: crate::model::PeerPathFilter::Applied,
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

impl CaptureArtifacts {
    fn manifest_records(&self, directory: &Path) -> Result<Vec<QaArtifact>> {
        Ok(vec![
            QaArtifact::read(directory, &self.text, "text/plain; charset=utf-8")?,
            QaArtifact::read(directory, &self.svg, "image/svg+xml")?,
        ])
    }
}

impl NativeCaptureArtifacts {
    fn manifest_records(&self, directory: &Path) -> Result<Vec<QaArtifact>> {
        Ok(vec![
            QaArtifact::read(directory, &self.text, "text/plain; charset=utf-8")?,
            QaArtifact::read(
                directory,
                &self.ansi,
                "application/vnd.linktop.terminal-ansi",
            )?,
            QaArtifact::read(directory, &self.html, "text/html; charset=utf-8")?,
        ])
    }
}

impl QaArtifact {
    fn read(directory: &Path, path: &Path, media_type: &'static str) -> Result<Self> {
        let name = relative_artifact_name(directory, path)?;
        let bytes =
            fs::read(path).with_context(|| format!("read QA artifact {}", path.display()))?;
        Ok(Self {
            name,
            media_type,
            byte_length: u64::try_from(bytes.len()).context("QA artifact is too large")?,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        })
    }
}

fn relative_artifact_name(directory: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(directory).with_context(|| {
        format!(
            "QA artifact {} is outside capture directory {}",
            path.display(),
            directory.display()
        )
    })?;
    let mut components = relative.components();
    let component = components
        .next()
        .context("QA artifact name must not be empty")?;
    anyhow::ensure!(
        components.next().is_none()
            && matches!(component, std::path::Component::Normal(_))
            && !relative.is_absolute(),
        "QA artifact name must be one relative path component"
    );
    relative
        .to_str()
        .map(str::to_owned)
        .context("QA artifact name is not valid UTF-8")
}

fn write_manifest(directory: &Path, stem: &str, manifest: &QaCaptureManifest) -> Result<PathBuf> {
    let path = directory.join(format!("{stem}.json"));
    let temporary = directory.join(format!(".{stem}.tmp-{}", std::process::id()));
    ensure_path_absent(&path, "QA manifest")?;
    let mut temporary_created = false;
    let result = (|| -> Result<()> {
        let mut document =
            serde_json::to_vec_pretty(manifest).context("serialize QA capture manifest")?;
        document.push(b'\n');
        write_private_new(&temporary, &document)?;
        temporary_created = true;
        verify_manifest_artifacts(directory, manifest)?;
        publish_private_new(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() && temporary_created {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(path)
}

fn publish_private_new(temporary: &Path, path: &Path) -> Result<()> {
    fs::hard_link(temporary, path)
        .with_context(|| format!("publish new QA capture manifest {}", path.display()))?;
    // The final name now references a complete inode. Failure to remove the
    // private temporary name cannot make the published manifest incomplete.
    let _ = fs::remove_file(temporary);
    Ok(())
}

fn verify_manifest_publication_support(directory: &Path) -> Result<()> {
    let sequence = QA_PREFLIGHT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let identity = format!("{}-{sequence}", std::process::id());
    let temporary = directory.join(format!(".linktop-hard-link-probe-{identity}.tmp"));
    let published = directory.join(format!(".linktop-hard-link-probe-{identity}.published"));
    write_private_new(&temporary, b"linktop manifest publication preflight\n")?;
    let linked = fs::hard_link(&temporary, &published);
    let _ = fs::remove_file(&temporary);
    if let Err(error) = linked {
        anyhow::bail!(
            "QA capture output filesystem must support same-directory hard links for atomic no-clobber manifest publication: {error}"
        );
    }
    fs::remove_file(&published).with_context(|| {
        format!(
            "remove QA manifest publication preflight {}",
            published.display()
        )
    })?;
    Ok(())
}

fn verify_manifest_artifacts(directory: &Path, manifest: &QaCaptureManifest) -> Result<()> {
    anyhow::ensure!(
        !manifest.transaction_id.is_empty()
            && manifest.transaction_id.len() <= 128
            && manifest
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "QA manifest transaction ID is not a bounded portable identifier"
    );
    for (field, timestamp) in [
        ("started_at", manifest.started_at.as_str()),
        ("completed_at", manifest.completed_at.as_str()),
    ] {
        anyhow::ensure!(
            timestamp.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(timestamp).is_ok(),
            "QA manifest {field} is not an RFC 3339 UTC timestamp"
        );
    }
    anyhow::ensure!(
        manifest.producer.executable_sha256.len() == 64
            && manifest
                .producer
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "QA manifest producer executable digest is not lowercase SHA-256"
    );
    anyhow::ensure!(
        manifest.frames.len() == manifest.replay.frames_ms.len(),
        "QA manifest has {} completed frames for {} requested frame times",
        manifest.frames.len(),
        manifest.replay.frames_ms.len()
    );
    let maximum_frame_ms = manifest
        .frames
        .iter()
        .map(|frame| frame.actual_ms)
        .max()
        .unwrap_or(0);
    anyhow::ensure!(
        manifest.duration_ms >= maximum_frame_ms,
        "QA manifest duration ends before its final completed frame"
    );
    let mut names = BTreeSet::new();
    let mut previous_actual_ms = None;
    for (offset, (frame, requested_ms)) in manifest
        .frames
        .iter()
        .zip(&manifest.replay.frames_ms)
        .enumerate()
    {
        anyhow::ensure!(
            frame.index == offset + 1 && frame.scheduled_ms == *requested_ms,
            "QA frame {} does not match normalized requested frame {}ms",
            frame.index,
            requested_ms
        );
        anyhow::ensure!(
            frame.actual_ms >= frame.scheduled_ms,
            "QA frame {} was recorded before its scheduled time",
            frame.index
        );
        anyhow::ensure!(
            previous_actual_ms.is_none_or(|previous| frame.actual_ms >= previous),
            "QA frame {} actual time precedes the previous completed frame",
            frame.index
        );
        previous_actual_ms = Some(frame.actual_ms);
        anyhow::ensure!(
            !frame.artifacts.is_empty(),
            "QA frame {} has no completed artifacts",
            frame.index
        );
        for expected in &frame.artifacts {
            anyhow::ensure!(
                names.insert(expected.name.as_str()),
                "QA artifact {:?} appears more than once in the manifest",
                expected.name
            );
            let path = directory.join(&expected.name);
            let actual = QaArtifact::read(directory, &path, expected.media_type)?;
            anyhow::ensure!(
                actual.byte_length == expected.byte_length && actual.sha256 == expected.sha256,
                "QA artifact {:?} changed before manifest completion",
                expected.name
            );
        }
    }
    Ok(())
}

fn write_frame(directory: &Path, stem: &str, buffer: &Buffer) -> Result<CaptureArtifacts> {
    let text = directory.join(format!("{stem}.txt"));
    let svg = directory.join(format!("{stem}.svg"));
    write_private_new(&text, buffer_text(buffer).as_bytes())?;
    write_private_new(&svg, buffer_svg(buffer).as_bytes())?;
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
    write_private_new(&text, text_frame.as_bytes())?;
    write_private_new(&ansi, ansi_frame.as_bytes())?;
    write_private_new(&html, document.as_bytes())?;
    Ok(NativeCaptureArtifacts { text, ansi, html })
}

fn ensure_path_absent(path: &Path, kind: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {kind} path {}", path.display())),
        Ok(_) => anyhow::bail!("{kind} path already exists: {}", path.display()),
    }
}

fn write_private_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create private QA artifact {}", path.display()))?;
        created = true;
        private_file(path)?;
        file.write_all(contents)
            .with_context(|| format!("write private QA artifact {}", path.display()))?;
        file.flush()
            .with_context(|| format!("flush private QA artifact {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(path);
    }
    result
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
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use ratatui::layout::Rect;

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let serial = NEXT_TEST_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("linktop-{label}-{}-{serial}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
        assert!("2:40x8".parse::<ScheduledResize>().is_ok());
        assert!("2:39x20".parse::<ScheduledResize>().is_err());
        assert!("2:80x7".parse::<ScheduledResize>().is_err());
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

        let pause = ["2:p".parse::<ScheduledKey>().unwrap()];
        assert!(ReplayPlan::new(&[5], &pause, &[], Some(CaptureScene::WifiHotspotWifi)).is_err());
    }

    #[test]
    fn timed_scene_transitions_are_receipted_and_run_between_frames() {
        let plan =
            ReplayPlan::new(&[1, 3, 5, 7], &[], &[], Some(CaptureScene::WifiHotspotWifi)).unwrap();

        assert_eq!(
            plan.timestamps,
            [1, 2, 3, 4, 5, 7]
                .into_iter()
                .map(Duration::from_secs)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            plan.scene_stages,
            vec![
                QaSceneStage {
                    at_ms: 0,
                    stage: "wifi-initial",
                },
                QaSceneStage {
                    at_ms: 2_000,
                    stage: "hotspot-attached",
                },
                QaSceneStage {
                    at_ms: 4_000,
                    stage: "wifi-returned",
                },
            ]
        );
        let frame = qa_frame(
            QaFrameMetadata {
                index: 2,
                rendered_mode: MonitorMode::Overview,
                probe_policy: ProbePolicy::Passive,
                scene: Some(CaptureScene::WifiHotspotWifi),
                scheduled: Duration::from_secs(3),
                actual: Duration::from_millis(3_010),
                viewport: CaptureSize {
                    columns: 60,
                    rows: 10,
                },
            },
            Vec::new(),
        );
        assert_eq!(frame.stage, "hotspot-attached");
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
    fn frame_names_and_manifest_view_follow_replayed_navigation() {
        let mut app = App::with_probe_policy(ProbePolicy::Passive);
        let (controls, _controls_rx) = mpsc::channel();
        let mut interaction = InteractionState {
            active_mode: MonitorMode::Overview,
            peer_offset: 0,
            peer_selection: None,
            can_navigate: true,
        };
        apply_tui_key(
            &mut app,
            &controls,
            &mut interaction,
            ReplayKey::Peers.key_code(),
            1,
        );
        assert_eq!(interaction.active_mode, MonitorMode::Peers);
        let stem = FrameName {
            subject: subject_name(interaction.active_mode),
            scene: Some(CaptureScene::DensePeers),
            session: "session",
            native: false,
            index: 1,
            size: CaptureSize {
                columns: 80,
                rows: 20,
            },
            scheduled: Duration::from_secs(1),
            actual: Duration::from_millis(1_004),
        }
        .stem();
        assert!(stem.starts_with("peers-dense-peers-session-frame001-"));

        apply_tui_key(
            &mut app,
            &controls,
            &mut interaction,
            ReplayKey::Tab.key_code(),
            1,
        );
        assert_eq!(interaction.active_mode, MonitorMode::Overview);
        apply_tui_key(
            &mut app,
            &controls,
            &mut interaction,
            ReplayKey::Active.key_code(),
            1,
        );
        assert_eq!(app.probe_policy(), ProbePolicy::Active);
    }

    #[test]
    fn native_child_environment_clears_host_history_and_stale_scene_defaults() {
        let mut command = Command::new("linktop");
        command.env("LINKTOP_HISTORY", "/private/host-history.jsonl");
        command.env(SCREENSHOT_CHILD_SCENE, "stale-scene");
        command.env(SCREENSHOT_CHILD_SCENE_GATE, "/private/stale-gate");
        let gate = Path::new("/private/session-gate");
        configure_native_environment(
            &mut command,
            Some(CaptureScene::WifiHotspotWifi),
            Some(gate),
        );

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
            Some(std::ffi::OsStr::new("wifi-hotspot-wifi"))
        );
        assert_eq!(
            environment
                .get(std::ffi::OsStr::new(SCREENSHOT_CHILD_SCENE_GATE))
                .and_then(|value| value.as_deref()),
            Some(gate.as_os_str())
        );
    }

    #[test]
    fn scene_environment_requires_explicit_internal_child_authority() {
        assert!(child_scene_from_environment(false).unwrap().is_none());
        assert!(
            child_scene_from_values(Some(OsString::from("dense-peers")), None)
                .unwrap()
                .is_some()
        );
        assert!(child_scene_from_values(None, None).is_err());
    }

    #[test]
    fn native_scene_gate_is_private_and_removed_with_its_guard() {
        let directory = TestDirectory::new("native-scene-gate");
        let path;
        {
            let mut gate = SceneGate::new(&directory.0, "transaction").unwrap();
            path = gate.path().to_owned();
            assert!(!path.exists());
            gate.open().unwrap();
            assert!(scene_gate_is_open(&path).unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert!(!path.exists());
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
    fn wifi_hotspot_return_scene_uses_typed_history_and_path_generations() {
        let mut app = App::with_probe_policy(ProbePolicy::Passive);
        let mut runtime = SceneRuntime::new(CaptureScene::WifiHotspotWifi, None).unwrap();
        assert_eq!(
            runtime.native_expectation_at(Duration::from_secs(1)),
            Some(NativeSceneExpectation {
                scene: CaptureScene::WifiHotspotWifi,
                stage: "wifi-initial",
                generation: 1,
                path_marker: "Northstar Lab".into(),
            })
        );
        assert_eq!(
            runtime.native_expectation_at(Duration::from_secs(3)),
            Some(NativeSceneExpectation {
                scene: CaptureScene::WifiHotspotWifi,
                stage: "hotspot-attached",
                generation: 2,
                path_marker: "Field Kit".into(),
            })
        );
        assert_eq!(
            runtime.native_expectation_at(Duration::from_secs(5)),
            Some(NativeSceneExpectation {
                scene: CaptureScene::WifiHotspotWifi,
                stage: "wifi-returned",
                generation: 3,
                path_marker: "Northstar Lab".into(),
            })
        );

        runtime
            .advance_to(&mut app, Duration::from_secs(1))
            .unwrap();
        assert_eq!(app.path_generation, 1);
        assert_eq!(app.link.ssid.as_deref(), Some("Northstar Lab"));
        assert_eq!(
            app.history_context.as_ref().map(|context| context.kind),
            Some(crate::model::HistoryContextKind::FirstObservation)
        );

        runtime
            .advance_to(&mut app, Duration::from_secs(3))
            .unwrap();
        assert_eq!(app.path_generation, 2);
        assert_eq!(app.link.ssid.as_deref(), Some("Field Kit"));
        assert_eq!(
            app.history_context.as_ref().map(|context| context.kind),
            Some(crate::model::HistoryContextKind::Changed)
        );
        assert_eq!(app.completed_path_dwells.len(), 1);
        let first_window = app
            .latest_completed_path_window(MonitorMode::Overview)
            .expect("transition retains the previous Wi-Fi window");
        assert_eq!(first_window.generation, 1);
        assert_eq!(first_window.completed_by.next_generation, 2);
        assert_eq!(
            first_window.path_identity.ssid.as_deref(),
            Some("Northstar Lab")
        );
        assert_eq!(first_window.retained_completed_windows, 1);
        assert!(first_window.limitations.iter().any(|limitation| matches!(
            limitation,
            crate::model::CompletedPathWindowLimitation::NotCurrentPathEvidence
        )));

        runtime
            .advance_to(&mut app, Duration::from_secs(5))
            .unwrap();
        assert_eq!(app.path_generation, 3);
        assert_eq!(app.link.ssid.as_deref(), Some("Northstar Lab"));
        assert_eq!(
            app.history_context.as_ref().map(|context| context.kind),
            Some(crate::model::HistoryContextKind::Returned)
        );
        assert_eq!(app.completed_path_dwells.len(), 2);
        let returned_window = app
            .latest_completed_path_window(MonitorMode::Overview)
            .expect("return retains the completed hotspot window");
        assert_eq!(returned_window.generation, 2);
        assert_eq!(returned_window.completed_by.next_generation, 3);
        assert_eq!(
            returned_window.path_identity.ssid.as_deref(),
            Some("Field Kit")
        );
        assert_eq!(returned_window.retained_completed_windows, 2);
        assert_eq!(
            returned_window.interface.state,
            crate::model::CompletedPathWindowSupportState::Unavailable
        );
        assert_eq!(
            returned_window.radio.state,
            crate::model::CompletedPathWindowSupportState::Unavailable
        );
        assert_eq!(
            returned_window.workload.state,
            crate::model::CompletedPathWindowSupportState::Unavailable
        );
        assert_eq!(
            returned_window.neighbors.state,
            crate::model::CompletedPathWindowSupportState::Unavailable
        );

        runtime
            .advance_to(&mut app, Duration::from_secs(30))
            .unwrap();
        assert_eq!(app.path_generation, 3);
        assert_eq!(app.completed_path_dwells.len(), 2);
    }

    #[test]
    fn wifi_hotspot_return_scene_preserves_operator_priority_at_every_qa_size() {
        let mut app = App::with_probe_policy(ProbePolicy::Passive);
        let mut runtime = SceneRuntime::new(CaptureScene::WifiHotspotWifi, None).unwrap();
        for (elapsed, network) in [
            (1, "Northstar Lab"),
            (3, "Field Kit"),
            (5, "Northstar Lab"),
            (7, "Northstar Lab"),
        ] {
            runtime
                .advance_to(&mut app, Duration::from_secs(elapsed))
                .unwrap();
            for (width, height) in [(60, 10), (100, 24), (160, 30)] {
                let backend = TestBackend::new(width, height);
                let mut terminal = Terminal::new(backend).unwrap();
                terminal
                    .draw(|frame| ui::render(frame, &app, MonitorMode::Overview, 0, true))
                    .unwrap();
                let rendered = buffer_text(terminal.backend().buffer());
                assert!(
                    rendered.contains(network),
                    "{elapsed}s {width}x{height}\n{rendered}"
                );
                assert!(
                    rendered.contains("UNTESTED"),
                    "{elapsed}s {width}x{height}\n{rendered}"
                );
                assert!(
                    rendered.contains("PASSIVE"),
                    "{elapsed}s {width}x{height}\n{rendered}"
                );
                assert!(!rendered.to_lowercase().contains("owner"));
                assert!(!rendered.contains("location:"));
                assert!(!rendered.contains("802.11 roam"));
                let context_is_visible = match elapsed {
                    1 => rendered.contains("first observation"),
                    3 => {
                        rendered.contains("new network context") || rendered.contains("new context")
                    }
                    5 | 7 => rendered.contains("returned"),
                    _ => unreachable!(),
                };
                if height == 10 {
                    assert!(rendered.contains("path"), "{rendered}");
                    assert!(rendered.contains("coverage"), "{rendered}");
                    assert!(
                        rendered.contains("next: [a] run bounded path probes"),
                        "{rendered}"
                    );
                    assert!(!context_is_visible, "{rendered}");
                    assert!(!rendered.contains("prior path"), "{rendered}");
                } else {
                    assert!(context_is_visible, "{rendered}");
                }
                if elapsed == 7 && (width, height) == (160, 30) {
                    assert!(
                        rendered.contains("PATH WINDOWS / PROCESS LOCAL"),
                        "{rendered}"
                    );
                    assert!(rendered.contains("prior path"), "{rendered}");
                    assert!(rendered.contains("g2"), "{rendered}");
                    assert!(rendered.contains("Field Kit"), "{rendered}");
                    assert!(rendered.contains("prior support"), "{rendered}");
                    assert!(
                        rendered.contains("unavailable: counters, radio, workload, cache"),
                        "{rendered}"
                    );
                    assert!(!rendered.contains("counters +"), "{rendered}");
                    let history = rendered
                        .lines()
                        .find(|line| line.contains("history"))
                        .expect("wide transition view retains history context");
                    assert!(!history.contains('…'), "{history}");
                }
            }
        }
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

    #[test]
    fn native_plain_frame_is_derived_from_the_same_ansi_snapshot() {
        let ansi = "\u{1b}[36mLINKTOP\u{1b}[0m  PASSIVE";
        assert_eq!(strip_ansi_escapes::strip_str(ansi), "LINKTOP  PASSIVE");
    }

    #[cfg(unix)]
    #[test]
    fn artifact_writer_rejects_preexisting_symlinks_without_touching_target() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("qa-artifact-symlink");
        let target = directory.0.join("outside-target");
        let artifact = directory.0.join("frame.txt");
        fs::write(&target, b"preserve\n").unwrap();
        symlink(&target, &artifact).unwrap();

        assert!(write_private_new(&artifact, b"replacement\n").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve\n");
        assert!(
            fs::symlink_metadata(&artifact)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn native_view_verification_binds_manifest_identity_to_visible_header() {
        verify_captured_state(
            "│ LINKTOP   NETWORK CONTEXT  PASSIVE │",
            MonitorMode::Overview,
            ProbePolicy::Passive,
        )
        .unwrap();
        verify_captured_state(
            "│ LINKTOP   LOCAL LINK / PASSIVE  OBSERVED │",
            MonitorMode::Link,
            ProbePolicy::Passive,
        )
        .unwrap();
        verify_captured_state(
            "│ LINKTOP   NEIGHBORS / ACTIVE  OK │",
            MonitorMode::Peers,
            ProbePolicy::Active,
        )
        .unwrap();
        assert!(
            verify_captured_state(
                "│ LINKTOP   LOCAL LINK / PASSIVE  OBSERVED │",
                MonitorMode::Peers,
                ProbePolicy::Passive,
            )
            .is_err()
        );
        assert!(
            verify_captured_state(
                "│ LINKTOP   NEIGHBORS / PASSIVE  OK │",
                MonitorMode::Peers,
                ProbePolicy::Active,
            )
            .is_err()
        );
        assert!(
            verify_captured_state(
                "┌ LIVE STATUS ┐\n│ LINKTOP   NEIGHBORS / ACTIVE  OK │\n└─────────────┘\n┌ PASSIVE NEIGHBORS ┐",
                MonitorMode::Peers,
                ProbePolicy::Passive,
            )
            .is_err()
        );
    }

    #[test]
    fn native_scene_readiness_accepts_generation_only_in_the_size_fallback() {
        let expectation = NativeSceneExpectation {
            scene: CaptureScene::WifiHotspotWifi,
            stage: "hotspot-attached",
            generation: 2,
            path_marker: "Field Kit".into(),
        };

        assert!(native_scene_stage_visible(
            "OVERVIEW · PASSIVE · LIVE\nPATH GEN 2\nresize to inspect evidence",
            &expectation,
        ));
        assert!(native_scene_stage_visible(
            "LINKTOP NETWORK CONTEXT PATH GEN 2\npath en0 / Field Kit",
            &expectation,
        ));
        assert!(!native_scene_stage_visible(
            "OVERVIEW · PASSIVE · LIVE\nPATH GEN 1\nresize to inspect evidence",
            &expectation,
        ));
        assert!(!native_scene_stage_visible(
            "LINKTOP NETWORK CONTEXT PATH GEN 2\npath en0 / another network",
            &expectation,
        ));
    }

    #[test]
    fn qa_manifest_is_pretty_versioned_and_written_after_complete_artifacts() {
        let directory = TestDirectory::new("qa-manifest-golden");
        let artifact_path = directory.0.join("peers-frame001.txt");
        fs::write(&artifact_path, b"frame\n").unwrap();
        let artifact =
            QaArtifact::read(&directory.0, &artifact_path, "text/plain; charset=utf-8").unwrap();
        let replay = ReplayPlan::new(
            &[1],
            &[
                "1:a".parse::<ScheduledKey>().unwrap(),
                "1:3".parse::<ScheduledKey>().unwrap(),
            ],
            &["1:80x20".parse::<ScheduledResize>().unwrap()],
            None,
        )
        .unwrap()
        .manifest_replay();
        let manifest = qa_manifest(
            QaManifestMetadata {
                transaction_id: "transaction-001".into(),
                started_at: "2026-07-26T18:00:00.000Z".into(),
                completed_at: "2026-07-26T18:00:01.004Z".into(),
                duration_ms: 1_004,
                native: false,
                requested_mode: MonitorMode::Overview,
                probe_policy: ProbePolicy::Passive,
                scene: None,
                executable_sha256:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            },
            replay,
            vec![qa_frame(
                QaFrameMetadata {
                    index: 1,
                    rendered_mode: MonitorMode::Peers,
                    probe_policy: ProbePolicy::Active,
                    scene: None,
                    scheduled: Duration::from_secs(1),
                    actual: Duration::from_millis(1_004),
                    viewport: CaptureSize {
                        columns: 80,
                        rows: 20,
                    },
                },
                vec![artifact],
            )],
        );

        let mut invalid = manifest.clone();
        invalid.transaction_id = "not/portable".into();
        assert!(verify_manifest_artifacts(&directory.0, &invalid).is_err());
        let mut invalid = manifest.clone();
        invalid.started_at = "2026-07-26 18:00:00".into();
        assert!(verify_manifest_artifacts(&directory.0, &invalid).is_err());
        let mut invalid = manifest.clone();
        invalid.duration_ms = 1_003;
        assert!(verify_manifest_artifacts(&directory.0, &invalid).is_err());
        let mut invalid = manifest.clone();
        invalid.replay.frames_ms.push(1_001);
        let mut second = invalid.frames[0].clone();
        second.index = 2;
        second.scheduled_ms = 1_001;
        second.actual_ms = 1_003;
        invalid.frames.push(second);
        let error = verify_manifest_artifacts(&directory.0, &invalid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("precedes the previous completed frame"));

        let manifest_path = write_manifest(&directory.0, "capture", &manifest).unwrap();
        let document = fs::read_to_string(manifest_path).unwrap();
        let expected =
            include_str!("capture/fixtures/v1/qa_capture_manifest.json").replace("\r\n", "\n");
        assert_eq!(
            document, expected,
            "golden manifest must match after normalizing checkout line endings"
        );
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(value["schema"], QA_MANIFEST_SCHEMA);
        assert_eq!(value["initial_policy"], "passive");
        assert_eq!(value["frames"][0]["rendered_view"], "peers");
        assert_eq!(value["frames"][0]["policy"], "active");
        assert!(
            value["frames"][0]["artifacts"][0]["name"]
                .as_str()
                .is_some_and(|name| !Path::new(name).is_absolute())
        );
    }

    #[test]
    fn qa_manifest_is_absent_when_a_requested_frame_is_incomplete() {
        let directory = TestDirectory::new("qa-manifest-incomplete");
        let manifest = qa_manifest(
            QaManifestMetadata {
                transaction_id: "transaction-incomplete".into(),
                started_at: "2026-07-26T18:00:00.000Z".into(),
                completed_at: "2026-07-26T18:00:01.000Z".into(),
                duration_ms: 1_000,
                native: false,
                requested_mode: MonitorMode::Overview,
                probe_policy: ProbePolicy::Passive,
                scene: None,
                executable_sha256:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            },
            QaReplay {
                frames_ms: vec![1_000, 2_000],
                keys: Vec::new(),
                resizes: Vec::new(),
                scene_stages: Vec::new(),
            },
            Vec::new(),
        );
        let path = directory.0.join("capture.json");
        assert!(write_manifest(&directory.0, "capture", &manifest).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn qa_manifest_is_absent_when_artifact_integrity_changes() {
        let directory = TestDirectory::new("qa-manifest-integrity");
        let artifact_path = directory.0.join("overview-frame001.txt");
        fs::write(&artifact_path, b"original\n").unwrap();
        let artifact =
            QaArtifact::read(&directory.0, &artifact_path, "text/plain; charset=utf-8").unwrap();
        fs::write(&artifact_path, b"changed\n").unwrap();
        let manifest = qa_manifest(
            QaManifestMetadata {
                transaction_id: "transaction-integrity".into(),
                started_at: "2026-07-26T18:00:00.000Z".into(),
                completed_at: "2026-07-26T18:00:01.001Z".into(),
                duration_ms: 1_001,
                native: false,
                requested_mode: MonitorMode::Overview,
                probe_policy: ProbePolicy::Passive,
                scene: None,
                executable_sha256:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            },
            QaReplay {
                frames_ms: vec![1_000],
                keys: Vec::new(),
                resizes: Vec::new(),
                scene_stages: Vec::new(),
            },
            vec![qa_frame(
                QaFrameMetadata {
                    index: 1,
                    rendered_mode: MonitorMode::Overview,
                    probe_policy: ProbePolicy::Passive,
                    scene: None,
                    scheduled: Duration::from_secs(1),
                    actual: Duration::from_millis(1_001),
                    viewport: CaptureSize {
                        columns: 80,
                        rows: 20,
                    },
                },
                vec![artifact],
            )],
        );
        let path = directory.0.join("capture.json");
        assert!(write_manifest(&directory.0, "capture", &manifest).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn manifest_publication_cannot_replace_a_concurrently_created_path() {
        let directory = TestDirectory::new("qa-manifest-no-clobber");
        let temporary = directory.0.join(".capture.tmp");
        let published = directory.0.join("capture.json");
        fs::write(&temporary, b"new manifest\n").unwrap();
        fs::write(&published, b"existing manifest\n").unwrap();

        assert!(publish_private_new(&temporary, &published).is_err());
        assert_eq!(fs::read(&published).unwrap(), b"existing manifest\n");
        assert_eq!(fs::read(&temporary).unwrap(), b"new manifest\n");
    }

    #[test]
    fn manifest_failure_does_not_remove_a_preexisting_temporary_path() {
        let directory = TestDirectory::new("qa-manifest-temp-no-clobber");
        let temporary = directory
            .0
            .join(format!(".capture.tmp-{}", std::process::id()));
        fs::write(&temporary, b"other transaction\n").unwrap();
        let manifest = qa_manifest(
            QaManifestMetadata {
                transaction_id: "transaction-temp-no-clobber".into(),
                started_at: "2026-07-26T18:00:00.000Z".into(),
                completed_at: "2026-07-26T18:00:01.000Z".into(),
                duration_ms: 1_000,
                native: false,
                requested_mode: MonitorMode::Overview,
                probe_policy: ProbePolicy::Passive,
                scene: None,
                executable_sha256:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            },
            QaReplay {
                frames_ms: Vec::new(),
                keys: Vec::new(),
                resizes: Vec::new(),
                scene_stages: Vec::new(),
            },
            Vec::new(),
        );

        assert!(write_manifest(&directory.0, "capture", &manifest).is_err());
        assert_eq!(fs::read(&temporary).unwrap(), b"other transaction\n");
        assert!(!directory.0.join("capture.json").exists());
    }

    #[test]
    fn capture_preflights_atomic_manifest_publication_in_the_output_directory() {
        let directory = TestDirectory::new("qa-manifest-preflight");
        verify_manifest_publication_support(&directory.0).unwrap();
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}
