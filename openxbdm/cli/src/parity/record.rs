//! Run a command list against a console and record each reply.

use std::io;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;

use super::error::RecordError;
use super::script::Command;
use super::script::Step;

/// Replies to one command list run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recording {
    /// Banner of the first connection; absent when none was opened.
    pub banner: Option<String>,
    pub exchanges: Vec<Exchange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exchange {
    pub command: String,
    pub reply: Reply,
}

/// A reply as seen on the wire. Text is escaped with [`escape`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Line {
        head: String,
    },
    /// `202`: lines up to the `.` line.
    Multiline {
        head: String,
        body: Vec<String>,
    },
    /// `203`: the payload is every byte up to the reply to a following
    /// `bye`, which the server reads only after the transfer ends.
    Binary {
        head: String,
        length: u64,
        /// FNV-1a 64 of the payload, as 16 hex digits.
        digest: String,
        end: BinaryEnd,
    },
    /// `204`: `after` is the reply to the uploaded data; absent when the
    /// command list supplies none, and the connection is then closed.
    Upload {
        head: String,
        after: Option<Box<Reply>>,
    },
    /// `205`: the connection became a notification or dedicated channel and
    /// is closed.
    Channel {
        head: String,
    },
    /// The server closed the connection before the reply was complete.
    Closed {
        received: String,
    },
    /// No complete reply arrived within the reply timeout.
    Timeout {
        received: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryEnd {
    /// The `200- bye` reply followed the payload.
    Bye,
    /// The server closed the connection without replying to `bye`.
    Closed,
}

/// The exchanges recorded up to the end of the command list or the error
/// that stopped the run.
#[derive(Debug)]
pub struct RecordOutcome {
    pub recording: Recording,
    pub error: Option<RecordError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineRead {
    Line,
    Closed,
}

/// Run `steps`, opening connections with `connect`. `progress` sees each
/// exchange as it completes.
pub async fn record<S, F, Fut>(
    steps: &[Step],
    connect: F,
    reply_timeout: Duration,
    progress: impl FnMut(&Exchange),
) -> RecordOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<S>>,
{
    let mut recording = Recording {
        banner: None,
        exchanges: Vec::new(),
    };
    let error = run_steps(steps, connect, reply_timeout, progress, &mut recording)
        .await
        .err();

    RecordOutcome { recording, error }
}

/// Printable ASCII is kept; a backslash becomes `\\` and other bytes
/// `\xNN`.
pub fn escape(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => text.push_str("\\\\"),
            0x20..=0x7e => text.push(char::from(byte)),
            _ => text.push_str(&format!("\\x{byte:02x}")),
        }
    }

    text
}

async fn run_steps<S, F, Fut>(
    steps: &[Step],
    mut connect: F,
    reply_timeout: Duration,
    mut progress: impl FnMut(&Exchange),
    recording: &mut Recording,
) -> Result<(), RecordError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<S>>,
{
    let mut connection: Option<BufReader<S>> = None;
    for step in steps {
        let command = match step {
            Step::Reconnect => {
                connection = None;
                continue;
            }
            Step::Command(command) => command,
        };

        let stream = match &mut connection {
            Some(stream) => stream,
            None => {
                let mut stream = BufReader::new(connect().await.map_err(RecordError::Connect)?);
                let mut line = Vec::new();
                let read = tokio::time::timeout(reply_timeout, read_line(&mut stream, &mut line))
                    .await
                    .map_err(|_| RecordError::BannerTimeout)?
                    .map_err(RecordError::Banner)?;
                if read == LineRead::Closed {
                    return Err(RecordError::BannerClosed);
                }

                recording
                    .banner
                    .get_or_insert_with(|| escape(trim_line(&line)));
                connection.insert(stream)
            }
        };

        let mut transcript = Vec::new();
        let outcome =
            tokio::time::timeout(reply_timeout, exchange(stream, command, &mut transcript)).await;
        let (reply, keep) = match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => (
                Reply::Closed {
                    received: escape(&transcript),
                },
                false,
            ),
            Err(_) => (
                Reply::Timeout {
                    received: escape(&transcript),
                },
                false,
            ),
        };
        if !keep {
            connection = None;
        }

        let exchange = Exchange {
            command: command.line.clone(),
            reply,
        };
        progress(&exchange);
        recording.exchanges.push(exchange);
    }

    Ok(())
}

/// Read through the next LF. A partial line at end of stream counts as
/// closed; its bytes stay in `line`.
async fn read_line<S>(stream: &mut BufReader<S>, line: &mut Vec<u8>) -> io::Result<LineRead>
where
    S: AsyncRead + Unpin,
{
    stream.read_until(b'\n', line).await?;

    Ok(if line.ends_with(b"\n") {
        LineRead::Line
    } else {
        LineRead::Closed
    })
}

fn trim_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Send one command and read its reply. Returns the reply and whether the
/// connection stays usable. Every byte read is appended to `transcript`.
async fn exchange<S>(
    stream: &mut BufReader<S>,
    command: &Command,
    transcript: &mut Vec<u8>,
) -> io::Result<(Reply, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = Vec::with_capacity(command.line.len() + 2);
    line.extend_from_slice(command.line.as_bytes());
    line.extend_from_slice(b"\r\n");
    stream.get_mut().write_all(&line).await?;

    let (reply, keep) = read_reply(stream, transcript).await?;
    let Reply::Upload { head, after: None } = reply else {
        return Ok((reply, keep));
    };

    let Some(data) = &command.upload else {
        return Ok((Reply::Upload { head, after: None }, false));
    };

    stream.get_mut().write_all(data).await?;
    let (after, keep) = read_reply(stream, transcript).await?;
    // A second `204` would take the following command lines as data.
    let keep = keep && !matches!(after, Reply::Upload { .. });

    Ok((
        Reply::Upload {
            head,
            after: Some(Box::new(after)),
        },
        keep,
    ))
}

/// Read one reply. A `204` is returned as an upload without `after`; the
/// caller decides whether to continue.
async fn read_reply<S>(
    stream: &mut BufReader<S>,
    transcript: &mut Vec<u8>,
) -> io::Result<(Reply, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const BYE_REPLY: &[u8] = b"200- bye\r\n";

    let start = transcript.len();
    if read_line(stream, transcript).await? == LineRead::Closed {
        return Ok((
            Reply::Closed {
                received: escape(transcript),
            },
            false,
        ));
    }

    let head = escape(trim_line(&transcript[start..]));
    let status = head.get(..3).unwrap_or_default();
    match status {
        "202" => {
            let mut body = Vec::new();
            loop {
                let start = transcript.len();
                if read_line(stream, transcript).await? == LineRead::Closed {
                    return Ok((
                        Reply::Closed {
                            received: escape(transcript),
                        },
                        false,
                    ));
                }

                let line = trim_line(&transcript[start..]);
                if line == b"." {
                    return Ok((Reply::Multiline { head, body }, true));
                }
                body.push(escape(line));
            }
        }
        "203" => {
            stream.get_mut().write_all(b"bye\r\n").await?;
            let start = transcript.len();
            stream.read_to_end(transcript).await?;

            let rest = &transcript[start..];
            let (payload, end) = match rest.strip_suffix(BYE_REPLY) {
                Some(payload) => (payload, BinaryEnd::Bye),
                None => (rest, BinaryEnd::Closed),
            };

            Ok((
                Reply::Binary {
                    head,
                    length: payload.len() as u64,
                    digest: format!("{:016x}", fnv1a64(payload)),
                    end,
                },
                false,
            ))
        }
        "204" => Ok((Reply::Upload { head, after: None }, true)),
        "205" => Ok((Reply::Channel { head }, false)),
        _ => Ok((Reply::Line { head }, true)),
    }
}

fn fnv1a64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parity::script;

    /// Serve each accepted connection from `replies`: after every received
    /// line, write the reply registered for it.
    fn scripted_server(
        replies: &'static [(&'static str, &'static [u8])],
    ) -> impl FnMut() -> std::future::Ready<io::Result<tokio::io::DuplexStream>> {
        move || {
            let (client, server) = tokio::io::duplex(1 << 16);
            tokio::spawn(async move {
                let (read, mut write) = tokio::io::split(server);
                let mut read = BufReader::new(read);
                write.write_all(b"201- connected\r\n").await.unwrap();
                let mut line = Vec::new();
                loop {
                    line.clear();
                    if read.read_until(b'\n', &mut line).await.unwrap() == 0 {
                        return;
                    }
                    let text = String::from_utf8_lossy(trim_line(&line)).into_owned();
                    let Some((_, reply)) = replies.iter().find(|(key, _)| *key == text) else {
                        // Upload payloads are answered by the `<upload>` entry.
                        let (_, reply) =
                            replies.iter().find(|(key, _)| *key == "<upload>").unwrap();
                        write.write_all(reply).await.unwrap();
                        continue;
                    };
                    write.write_all(reply).await.unwrap();
                    if text == "bye" || text == "close" {
                        return;
                    }
                }
            });
            std::future::ready(Ok(client))
        }
    }

    #[tokio::test]
    async fn records_every_reply_shape() {
        static REPLIES: &[(&str, &[u8])] = &[
            ("dmversion", b"200- 2.0.21256.0\r\n"),
            (
                "list",
                b"202- multiline response follows\r\na=1 b=\"x y\"\r\n\\\xff\r\n.\r\n",
            ),
            ("blob", b"203- binary response follows\r\nabc"),
            ("bye", b"200- bye\r\n"),
            ("send", b"204- send binary data\r\n"),
            ("<upload>", b"200- OK\r\n"),
            ("notify", b"205- now a notification channel\r\n"),
            ("close", b"200- partial"),
            ("", b"407- unknown command\r\n"),
        ];
        let steps = script::parse(
            "dmversion\nlist\nblob\ndmversion\nsend\n%upload 31320d0a\nsend\nnotify\n%send\nclose\ndmversion\n%reconnect\ndmversion\n",
        )
        .unwrap();
        let outcome = record(
            &steps,
            scripted_server(REPLIES),
            Duration::from_secs(5),
            |_| {},
        )
        .await;
        assert!(outcome.error.is_none());
        insta::assert_json_snapshot!(outcome.recording);
    }

    #[tokio::test]
    async fn records_a_timeout_and_reconnects() {
        static REPLIES: &[(&str, &[u8])] = &[
            ("slow", b"202- multiline response follows\r\npartial\r\n"),
            ("dmversion", b"200- 2.0.21256.0\r\n"),
        ];
        let steps = script::parse("slow\ndmversion\n").unwrap();
        let outcome = record(
            &steps,
            scripted_server(REPLIES),
            Duration::from_millis(200),
            |_| {},
        )
        .await;
        assert!(outcome.error.is_none());
        insta::assert_json_snapshot!(outcome.recording);
    }

    #[tokio::test]
    async fn keeps_the_exchanges_before_a_failed_connection() {
        static REPLIES: &[(&str, &[u8])] = &[("bye", b"200- bye\r\n")];
        let steps = script::parse("bye\n%reconnect\nbye\n").unwrap();
        let mut server = scripted_server(REPLIES);
        let mut connections = 0;
        let connect = || {
            connections += 1;
            let result = if connections == 1 {
                server().into_inner()
            } else {
                Err(io::Error::from(io::ErrorKind::ConnectionRefused))
            };
            std::future::ready(result)
        };
        let outcome = record(&steps, connect, Duration::from_secs(5), |_| {}).await;
        assert!(matches!(outcome.error, Some(RecordError::Connect(_))));
        insta::assert_json_snapshot!(outcome.recording);
    }
}
