//! Recording of the link command rustc runs and its replay with the
//! assembled module object in place of the LTO object.

use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

/// Linker rustc selects for the target (`"linker": "rust-lld"`).
pub const LINKER: &str = "rust-lld";

#[derive(Debug, Error)]
pub enum Error {
    #[error("linker argument {argument:?} is not UTF-8")]
    NotUtf8 { argument: OsString },
    #[error("linker argument {argument:?} contains a line break")]
    LineBreak { argument: String },
    #[error("expected one LTO object (`*-cgu.*.rcgu.o`) among the linker arguments, found {count}")]
    MainObjectCount { count: usize },
    #[error("`{name}` is not in PATH")]
    LinkerNotFound { name: &'static str },
    #[error("copying linker input {path}")]
    CopyInput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("reading the link record")]
    Read(#[source] io::Error),
    #[error("writing the link record")]
    Write(#[source] io::Error),
    #[error("link record line {line} is malformed")]
    MalformedRecord { line: usize },
    #[error("link record has no linker line")]
    MissingLinker,
    #[error("link record has no main object")]
    MissingMainObject,
    #[error("link record has no `-o` argument")]
    MissingOutput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Argument {
    Plain(String),
    /// The LTO object of the final crate; replaced on replay.
    MainObject(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRecord {
    pub linker: PathBuf,
    pub arguments: Vec<Argument>,
}

/// Searches `PATH` for the target linker.
pub fn find_linker() -> Result<PathBuf, Error> {
    let file = format!("{LINKER}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|directory| directory.join(&file))
        .find(|candidate| candidate.is_file())
        .ok_or(Error::LinkerNotFound { name: LINKER })
}

fn is_main_object(argument: &str) -> bool {
    let file_name = Path::new(argument)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(argument);
    file_name.ends_with(".rcgu.o") && file_name.contains("-cgu.")
}

impl LinkRecord {
    /// Records `arguments`. Other object files live in rustc's temporary
    /// directory, so they are copied to `inputs`.
    pub fn capture(linker: PathBuf, arguments: &[OsString], inputs: &Path) -> Result<Self, Error> {
        let mut recorded = Vec::with_capacity(arguments.len());
        let mut main_objects = 0;
        for (index, argument) in arguments.iter().enumerate() {
            let argument = argument.to_str().ok_or_else(|| Error::NotUtf8 {
                argument: argument.clone(),
            })?;
            if argument.contains(['\n', '\r']) {
                return Err(Error::LineBreak {
                    argument: argument.to_owned(),
                });
            }
            if is_main_object(argument) {
                main_objects += 1;
                recorded.push(Argument::MainObject(argument.to_owned()));
            } else if argument.ends_with(".o") && Path::new(argument).is_file() {
                let file_name = Path::new(argument)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("input.o");
                let copy = inputs.join(format!("{index}-{file_name}"));
                let copy_error = |source| Error::CopyInput {
                    path: PathBuf::from(argument),
                    source,
                };
                fs::create_dir_all(inputs).map_err(copy_error)?;
                fs::copy(argument, &copy).map_err(copy_error)?;
                let copy = copy
                    .into_os_string()
                    .into_string()
                    .map_err(|argument| Error::NotUtf8 { argument })?;
                recorded.push(Argument::Plain(copy));
            } else {
                recorded.push(Argument::Plain(argument.to_owned()));
            }
        }
        if main_objects != 1 {
            return Err(Error::MainObjectCount {
                count: main_objects,
            });
        }
        Ok(LinkRecord {
            linker,
            arguments: recorded,
        })
    }

    pub fn write(&self, mut out: impl Write) -> Result<(), Error> {
        writeln!(out, "linker\t{}", self.linker.display()).map_err(Error::Write)?;
        for argument in &self.arguments {
            match argument {
                Argument::Plain(value) => writeln!(out, "arg\t{value}"),
                Argument::MainObject(value) => writeln!(out, "main-object\t{value}"),
            }
            .map_err(Error::Write)?;
        }
        out.flush().map_err(Error::Write)
    }

    pub fn read(input: impl BufRead) -> Result<Self, Error> {
        let mut linker = None;
        let mut arguments = Vec::new();
        for (number, line) in input.lines().enumerate() {
            let line = line.map_err(Error::Read)?;
            let malformed = Error::MalformedRecord { line: number + 1 };
            let (tag, value) = line.split_once('\t').ok_or(malformed)?;
            match tag {
                "linker" => linker = Some(PathBuf::from(value)),
                "arg" => arguments.push(Argument::Plain(value.to_owned())),
                "main-object" => arguments.push(Argument::MainObject(value.to_owned())),
                _ => return Err(Error::MalformedRecord { line: number + 1 }),
            }
        }
        let linker = linker.ok_or(Error::MissingLinker)?;
        if !arguments
            .iter()
            .any(|argument| matches!(argument, Argument::MainObject(_)))
        {
            return Err(Error::MissingMainObject);
        }
        Ok(LinkRecord { linker, arguments })
    }

    /// The recorded command linking `object` instead of the LTO object into
    /// `output`. `keep_symbols` drops `--strip-all` for disassembly.
    pub fn command(
        &self,
        object: &Path,
        output: &Path,
        keep_symbols: bool,
    ) -> Result<Command, Error> {
        let mut command = Command::new(&self.linker);
        let mut replaced_output = false;
        let mut arguments = self.arguments.iter();
        while let Some(argument) = arguments.next() {
            match argument {
                Argument::MainObject(_) => {
                    command.arg(object);
                }
                Argument::Plain(value) if value == "-o" => {
                    arguments.next().ok_or(Error::MissingOutput)?;
                    command.arg("-o").arg(output);
                    replaced_output = true;
                }
                Argument::Plain(value)
                    if keep_symbols && (value == "--strip-all" || value == "-s") => {}
                Argument::Plain(value) => {
                    command.arg(value);
                }
            }
        }
        if !replaced_output {
            return Err(Error::MissingOutput);
        }
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn records_and_replays() {
        let record = LinkRecord::capture(
            PathBuf::from("/bin/rust-lld"),
            &arguments(&[
                "-flavor",
                "gnu",
                "/deps/m-5d34.m.f0ee-cgu.0.rcgu.o",
                "/deps/libcompiler_builtins-03f2.rlib",
                "-o",
                "/deps/m-5d34",
                "--gc-sections",
                "--strip-all",
            ]),
            Path::new("/nonexistent"),
        )
        .expect("capture");
        let mut text = Vec::new();
        record.write(&mut text).expect("write");
        let text = String::from_utf8(text).expect("utf-8");
        insta::assert_snapshot!(text, @r"
        linker	/bin/rust-lld
        arg	-flavor
        arg	gnu
        main-object	/deps/m-5d34.m.f0ee-cgu.0.rcgu.o
        arg	/deps/libcompiler_builtins-03f2.rlib
        arg	-o
        arg	/deps/m-5d34
        arg	--gc-sections
        arg	--strip-all
        ");
        let replayed = LinkRecord::read(text.as_bytes()).expect("read");
        assert_eq!(replayed, record);
        let command = replayed
            .command(Path::new("/s/module.o"), Path::new("/s/image"), true)
            .expect("command");
        let replayed: Vec<_> = command
            .get_args()
            .map(|a| a.to_str().expect("utf-8"))
            .collect();
        assert_eq!(
            replayed,
            [
                "-flavor",
                "gnu",
                "/s/module.o",
                "/deps/libcompiler_builtins-03f2.rlib",
                "-o",
                "/s/image",
                "--gc-sections"
            ]
        );
    }

    #[test]
    fn requires_one_lto_object() {
        let error = LinkRecord::capture(
            PathBuf::from("rust-lld"),
            &arguments(&["a-cgu.0.rcgu.o", "b-cgu.0.rcgu.o", "-o", "x"]),
            Path::new("/nonexistent"),
        )
        .expect_err("two objects");
        assert!(matches!(error, Error::MainObjectCount { count: 2 }));
    }
}
