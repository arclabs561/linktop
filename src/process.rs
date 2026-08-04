use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wait_timeout::ChildExt;

pub fn run_bounded(command: &mut Command, timeout: Duration) -> io::Result<Option<Output>> {
    run_bounded_with(command, timeout, || ()).map(|(output, ())| output)
}

/// Run one callback after the child has started and while its output is drained.
pub fn run_bounded_with<T>(
    command: &mut Command,
    timeout: Duration,
    after_spawn: impl FnOnce() -> T + Send,
) -> io::Result<(Option<Output>, T)>
where
    T: Send,
{
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().map(|mut stream| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).map(|_| bytes)
        })
    });
    let stderr = child.stderr.take().map(|mut stream| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).map(|_| bytes)
        })
    });
    let child_started = Instant::now();
    thread::scope(|scope| {
        let concurrent = scope.spawn(after_spawn);
        let remaining = timeout.saturating_sub(child_started.elapsed());
        let output = if let Some(status) = child.wait_timeout(remaining)? {
            Some(Output {
                status,
                stdout: join_reader(stdout)?,
                stderr: join_reader(stderr)?,
            })
        } else {
            let _ = child.kill();
            let _ = child.wait();
            join_reader(stdout)?;
            join_reader(stderr)?;
            None
        };
        let concurrent = concurrent
            .join()
            .map_err(|_| io::Error::other("after-spawn callback panicked"))?;
        Ok((output, concurrent))
    })
}

fn join_reader(reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    match reader {
        Some(reader) => reader
            .join()
            .map_err(|_| io::Error::other("output reader thread panicked"))?,
        None => Ok(Vec::new()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn captures_completed_output() {
        let output = run_bounded(
            Command::new("sh").args(["-c", "printf bounded"]),
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "bounded");
    }

    #[test]
    fn terminates_a_command_at_its_deadline() {
        let output = run_bounded(
            Command::new("sh").args(["-c", "sleep 2"]),
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(output.is_none());
    }

    #[test]
    fn callback_runs_after_spawn_and_before_wait() {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let marker = std::env::temp_dir().join(format!(
            "linktop-process-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let output = run_bounded_with(
            Command::new("sh").args([
                "-c",
                "while [ ! -f \"$1\" ]; do sleep 0.01; done; printf concurrent",
                "sh",
                marker.to_str().unwrap(),
            ]),
            Duration::from_secs(1),
            || std::fs::write(&marker, b"ready").unwrap(),
        )
        .unwrap()
        .0
        .unwrap();
        std::fs::remove_file(&marker).unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "concurrent");
    }

    #[test]
    fn callback_does_not_postpone_the_child_deadline() {
        let started = Instant::now();
        let output = run_bounded_with(
            Command::new("sleep").arg("1"),
            Duration::from_millis(20),
            || std::thread::sleep(Duration::from_millis(30)),
        )
        .unwrap()
        .0;
        assert!(output.is_none());
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
