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
    let stdout = child.stdout.take().map(spawn_reader);
    let stderr = child.stderr.take().map(spawn_reader);
    let child_started = Instant::now();
    thread::scope(|scope| {
        let concurrent = scope.spawn(after_spawn);
        let remaining = timeout.saturating_sub(child_started.elapsed());
        let output = if let Some(status) = child.wait_timeout(remaining)? {
            let budget = timeout.saturating_sub(child_started.elapsed());
            Some(Output {
                status,
                stdout: drain(stdout, budget),
                stderr: drain(stderr, budget),
            })
        } else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = drain(stdout, KILL_DRAIN_GRACE);
            let _ = drain(stderr, KILL_DRAIN_GRACE);
            None
        };
        let concurrent = concurrent
            .join()
            .map_err(|_| io::Error::other("after-spawn callback panicked"))?;
        Ok((output, concurrent))
    })
}

const DRAIN_CHUNK: usize = 8 * 1024;

/// After a timeout the killed child's pipes get this long to report the bytes
/// it had already written. A surviving grandchild may hold them open.
const KILL_DRAIN_GRACE: Duration = Duration::from_millis(50);

/// A pipe drained on its own thread, reporting chunks until it sees EOF.
///
/// Reading to end on the calling thread would let a grandchild that inherits
/// the pipe keep the deadline from ever being reached.
struct Reader(Option<std::sync::mpsc::Receiver<Vec<u8>>>);

fn spawn_reader<R: Read + Send + 'static>(mut stream: R) -> Reader {
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0u8; DRAIN_CHUNK];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    // A closed channel means the deadline passed and nobody is
                    // collecting; the read ends when the last writer closes.
                    if sender.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    Reader(Some(receiver))
}

/// Everything a pipe reported within `budget`, which is a partial transcript
/// when a writer outlived the deadline.
fn drain(reader: Option<Reader>, budget: Duration) -> Vec<u8> {
    let Some(Reader(Some(receiver))) = reader else {
        return Vec::new();
    };
    let deadline = Instant::now() + budget;
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(chunk) => bytes.extend_from_slice(&chunk),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return bytes,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return bytes,
        }
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

#[cfg(all(test, unix))]
mod bughunt_deadline {
    use super::*;

    // The bug hunt's repro: the shell exits at once, but a backgrounded
    // grandchild inherits stdout and holds the pipe open for ten seconds.
    #[test]
    fn deadline_holds_when_a_grandchild_keeps_stdout_open() {
        let started = Instant::now();
        let output = run_bounded(
            Command::new("sh").args(["-c", "sh -c 'sleep 10' & printf bounded; exit 0"]),
            Duration::from_millis(200),
        )
        .unwrap()
        .expect("child exits before the deadline");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "deadline took {elapsed:?}"
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "bounded");
    }

    #[test]
    fn a_killed_child_still_returns_before_the_deadline() {
        let started = Instant::now();
        let output = run_bounded(
            Command::new("sh").args(["-c", "printf partial; sleep 10"]),
            Duration::from_millis(200),
        )
        .unwrap();
        let elapsed = started.elapsed();
        assert!(output.is_none());
        assert!(
            elapsed < Duration::from_secs(2),
            "deadline took {elapsed:?}"
        );
    }
}
