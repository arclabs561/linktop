use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Local;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};

use crate::model::{App, MonitorControl, MonitorMode, ProbePolicy};
use crate::{net, process, ui};

const POLL_STEP: Duration = Duration::from_millis(100);
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

pub fn run(
    interval: Duration,
    mode: MonitorMode,
    probe_policy: ProbePolicy,
    requested_seconds: &[u64],
    size: CaptureSize,
    output_directory: &Path,
) -> Result<()> {
    let schedule = CaptureSchedule::new(requested_seconds)?;
    fs::create_dir_all(output_directory)
        .with_context(|| format!("create capture directory {}", output_directory.display()))?;
    private_directory(output_directory)?;

    let session = format!(
        "{}-{}",
        Local::now().format("%Y%m%dT%H%M%S"),
        std::process::id()
    );
    let subject = subject_name(mode);
    let backend = TestBackend::new(size.columns, size.rows);
    let mut terminal = Terminal::new(backend).context("create capture terminal")?;
    let (updates, controls, monitor) = net::start_monitor(interval, mode, probe_policy);
    let started_at = Instant::now();
    let mut app = App::with_probe_policy(probe_policy);
    let result = (|| -> Result<()> {
        for target in schedule.targets {
            wait_until(target, started_at, &updates, &mut app)?;
            drain_updates(&updates, &mut app)?;
            let frame = terminal
                .draw(|frame| ui::render(frame, &app, mode, 0, mode == MonitorMode::Overview))
                .context("render capture frame")?;
            let elapsed = started_at.elapsed();
            let stem = format!(
                "{subject}-{session}-{}x{}-at{:05}ms",
                size.columns,
                size.rows,
                elapsed.as_millis()
            );
            let artifacts = write_frame(output_directory, &stem, frame.buffer)?;
            println!(
                "captured {} at {:.1}s\n  text {}\n  image {}",
                subject,
                elapsed.as_secs_f64(),
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

pub fn run_native(
    interval: Duration,
    mode: MonitorMode,
    probe_policy: ProbePolicy,
    requested_seconds: &[u64],
    size: CaptureSize,
    output_directory: &Path,
) -> Result<()> {
    let schedule = CaptureSchedule::new(requested_seconds)?;
    fs::create_dir_all(output_directory)
        .with_context(|| format!("create capture directory {}", output_directory.display()))?;
    private_directory(output_directory)?;

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
    let final_seconds = schedule
        .targets
        .last()
        .expect("validated capture schedule is nonempty")
        .as_secs();

    let mut start = tmux_command(&server);
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
        .arg((final_seconds + 5).to_string());
    let output = process::run_bounded(&mut start, Duration::from_secs(5))
        .context("start native capture PTY")?
        .context("tmux did not start before its deadline")?;
    anyhow::ensure!(
        output.status.success(),
        "tmux failed to start native capture: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let _guard = TmuxGuard(server.clone());

    let started_at = Instant::now();
    for target in schedule.targets {
        wait_for_elapsed(target, started_at);
        let elapsed = started_at.elapsed();
        let stem = format!(
            "{subject}-{session_id}-native-{}x{}-at{:05}ms",
            size.columns,
            size.rows,
            elapsed.as_millis()
        );
        let artifacts = write_native_frame(
            output_directory,
            &stem,
            &capture_pane(&server, session, false)?,
            &capture_pane(&server, session, true)?,
        )?;
        println!(
            "captured native {} at {:.1}s\n  text {}\n  ansi {}\n  html {}",
            subject,
            elapsed.as_secs_f64(),
            artifacts.text.display(),
            artifacts.ansi.display(),
            artifacts.html.display()
        );
    }
    Ok(())
}

fn wait_for_elapsed(target: Duration, started_at: Instant) {
    loop {
        let remaining = target.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return;
        }
        thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

fn tmux_command(server: &str) -> Command {
    let mut command = Command::new("tmux");
    command.args(["-L", server, "-f", "/dev/null"]);
    command
}

fn capture_pane(server: &str, session: &str, styled: bool) -> Result<String> {
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
    anyhow::ensure!(
        frame.contains("LINKTOP"),
        "native terminal frame did not contain the Linktop view"
    );
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

fn wait_until(
    target: Duration,
    started_at: Instant,
    updates: &std::sync::mpsc::Receiver<crate::model::MonitorUpdate>,
    app: &mut App,
) -> Result<()> {
    loop {
        let remaining = target.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Ok(());
        }
        match updates.recv_timeout(remaining.min(POLL_STEP)) {
            Ok(update) => app.apply(update),
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
) -> Result<()> {
    loop {
        match updates.try_recv() {
            Ok(update) => app.apply(update),
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
