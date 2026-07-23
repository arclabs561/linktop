use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let view = arguments.next().unwrap_or_else(|| "overview".into());
    let columns = dimension(arguments.next(), 140, 60..=300, "columns")?;
    let rows = dimension(arguments.next(), 30, 12..=100, "rows")?;
    if arguments.next().is_some() {
        return Err("usage: capture_ui [overview|link|peers] [columns] [rows]".into());
    }
    if !matches!(view.as_str(), "overview" | "link" | "peers") {
        return Err(format!("unknown view {view:?}; expected overview, link, or peers").into());
    }

    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = repository.join("target/debug/linktop");
    if !binary.is_file() {
        return Err(
            "target/debug/linktop is missing; run `cargo build --bin linktop` first".into(),
        );
    }

    let output_directory = repository.join(".agents/reports/ui-captures");
    fs::create_dir_all(&output_directory)?;
    private_directory(&output_directory)?;
    let stem = format!("{view}-{columns}x{rows}");
    let text_path = output_directory.join(format!("{stem}.txt"));
    let image_path = output_directory.join(format!("{stem}.png"));

    let server = format!("linktop-capture-{}", std::process::id());
    let session = "capture";
    let mut start = Command::new("tmux");
    start
        .args(["-L", &server, "-f", "/dev/null"])
        .args(["new-session", "-d", "-s", session, "-x"])
        .arg(columns.to_string())
        .arg("-y")
        .arg(rows.to_string())
        .arg("-c")
        .arg(&repository)
        .arg(&binary);
    if view != "overview" {
        start.arg(&view);
    }
    start.args(["--interval", "1", "--dwell", "12"]);
    let status = start.status()?;
    if !status.success() {
        return Err(format!("tmux failed to start capture server {server}").into());
    }
    let _session = SessionGuard(server.clone());

    let mut frame = String::new();
    let mut settled_frames = 0;
    let settle_target = if view == "link" { 45 } else { 20 };
    for _ in 0..60 {
        thread::sleep(Duration::from_millis(200));
        let captured = Command::new("tmux")
            .args(["-L", &server, "-f", "/dev/null"])
            .args(["capture-pane", "-p", "-t", session])
            .output()?;
        if !captured.status.success() {
            break;
        }
        frame = String::from_utf8(captured.stdout)?;
        if frame.contains("LINKTOP") {
            settled_frames += 1;
            if settled_frames >= settle_target {
                break;
            }
        }
    }
    if !frame.contains("LINKTOP") {
        return Err("capture never observed the Linktop frame".into());
    }

    fs::write(&text_path, &frame)?;
    private_file(&text_path)?;
    let font = if Path::new("/System/Library/Fonts/Menlo.ttc").is_file() {
        "/System/Library/Fonts/Menlo.ttc"
    } else {
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    };
    let status = Command::new("magick")
        .args(["-background", "#11161c", "-fill", "#c0cad6"])
        .args(["-font", font, "-pointsize", "13"])
        .args(["-bordercolor", "#11161c"])
        .arg(format!("label:@{}", text_path.display()))
        .args(["-border", "18x18"])
        .arg(&image_path)
        .status()?;
    if !status.success() {
        return Err("ImageMagick failed to render the captured terminal frame".into());
    }
    private_file(&image_path)?;

    println!("text  {}", text_path.display());
    println!("image {}", image_path.display());
    Ok(())
}

fn dimension(
    value: Option<String>,
    default: u16,
    range: std::ops::RangeInclusive<u16>,
    label: &str,
) -> Result<u16, Box<dyn Error>> {
    let value = value.map_or(Ok(default), |value| value.parse::<u16>())?;
    if !range.contains(&value) {
        return Err(format!("{label} must be within {range:?}").into());
    }
    Ok(value)
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<(), Box<dyn Error>> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn private_file(_path: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

struct SessionGuard(String);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = Command::new("tmux")
            .args(["-L", &self.0, "-f", "/dev/null", "kill-server"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
