use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use wait_timeout::ChildExt;

pub fn run_bounded(command: &mut Command, timeout: Duration) -> io::Result<Option<Output>> {
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

    let Some(status) = child.wait_timeout(timeout)? else {
        let _ = child.kill();
        let _ = child.wait();
        join_reader(stdout)?;
        join_reader(stderr)?;
        return Ok(None);
    };

    Ok(Some(Output {
        status,
        stdout: join_reader(stdout)?,
        stderr: join_reader(stderr)?,
    }))
}

fn join_reader(reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    match reader {
        Some(reader) => reader
            .join()
            .map_err(|_| io::Error::other("output reader thread panicked"))?,
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn terminates_a_command_at_its_deadline() {
        let output = run_bounded(
            Command::new("sh").args(["-c", "sleep 2"]),
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(output.is_none());
    }
}
