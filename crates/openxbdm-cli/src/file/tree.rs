//! `file tree`: print a directory tree.

use std::io::IsTerminal;
use std::num::NonZeroU32;
use std::time::Duration;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use indicatif::ProgressBar;
use indicatif::ProgressDrawTarget;
use indicatif::ProgressStyle;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::DirEntry;
use openxbdm_client::commands::DirList;
use openxbdm_client::commands::DriveList;
use openxbdm_client::commands::remote_path;
use openxbdm_client::error::Error;
use owo_colors::OwoColorize;
use rootcause::Report;

use super::cmp_ignore_ascii_case;
use crate::ui::UiOptions;
use crate::ui::colors_enabled;
use crate::ui::ok_tag;

/// A listed directory whose entries are being printed.
struct TreeFrame {
    dir: String,
    depth: u32,
    entries: Vec<DirEntry>,
    next: usize,
}

/// Settings of one tree walk.
#[derive(Clone, Copy)]
struct Walk<'a> {
    max_depth: Option<NonZeroU32>,
    include_files: bool,
    ui: UiOptions,
    spinner: Option<&'a ProgressBar>,
}

impl Walk<'_> {
    /// Print `root` and its subtree, depth first. Unreadable directories are
    /// reported inline and skipped.
    async fn run<T>(self, client: &mut Client<T, Connected>, root: String, dir_count: &mut u64)
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.count_dir(dir_count);
        self.println(&dir_label(root.trim_end_matches('\\'), true));

        // One entry per frame above the root: whether that directory was
        // the last entry of its parent.
        let mut ancestors: Vec<bool> = Vec::new();
        let Some(entries) = self.read_dir(client, &root, &ancestors).await else {
            return;
        };
        let mut stack = vec![TreeFrame {
            dir: root,
            depth: 0,
            entries,
            next: 0,
        }];

        while let Some(frame) = stack.last_mut() {
            let Some(entry) = frame.entries.get(frame.next) else {
                stack.pop();
                ancestors.pop();
                continue;
            };
            frame.next += 1;
            let is_last = frame.next == frame.entries.len();

            self.println(&self.entry_line(entry, is_last, &ancestors));

            let child_depth = frame.depth + 1;
            let descend = entry.is_directory
                && self
                    .max_depth
                    .is_none_or(|max_depth| child_depth < max_depth.get());
            if !descend {
                continue;
            }

            let child_dir =
                remote_path::normalize_dir_path(&remote_path::join_path(&frame.dir, &entry.name));
            ancestors.push(is_last);
            self.count_dir(dir_count);
            let Some(entries) = self.read_dir(client, &child_dir, &ancestors).await else {
                ancestors.pop();
                continue;
            };
            stack.push(TreeFrame {
                dir: child_dir,
                depth: child_depth,
                entries,
                next: 0,
            });
        }
    }

    fn count_dir(self, dir_count: &mut u64) {
        *dir_count += 1;

        if let Some(bar) = self.spinner {
            bar.inc(1);
            bar.set_message(format!("{}", *dir_count));
        }
    }

    /// The entries of `dir` to print, directories first. On failure the
    /// reason is printed in place of the entries.
    async fn read_dir<T>(
        self,
        client: &mut Client<T, Connected>,
        dir: &str,
        ancestors: &[bool],
    ) -> Option<Vec<DirEntry>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut entries = match client
            .run(DirList {
                path: dir.to_owned(),
            })
            .await
        {
            Ok(entries) => entries,
            Err(err) => {
                let indent = tree_indent(ancestors, self.ui);
                let reason = format!("{:?}", err.current_context());
                let reason = if colors_enabled() {
                    format!("{}", reason.red())
                } else {
                    reason
                };
                self.println(&format!("{indent}(unreadable) {reason}"));
                return None;
            }
        };

        entries.retain(|entry| self.include_files || entry.is_directory);
        entries.sort_by(|a, b| {
            b.is_directory
                .cmp(&a.is_directory)
                .then_with(|| cmp_ignore_ascii_case(&a.name, &b.name))
        });

        Some(entries)
    }

    fn entry_line(self, entry: &DirEntry, is_last: bool, ancestors: &[bool]) -> String {
        let indent = tree_indent(ancestors, self.ui);
        let branch = match (self.ui.is_pretty(), is_last) {
            (true, true) => "\u{2514}\u{2500}\u{2500} ",
            (true, false) => "\u{251c}\u{2500}\u{2500} ",
            (false, true) => "`-- ",
            (false, false) => "|-- ",
        };
        let label = dir_label(&entry.name, entry.is_directory);

        if entry.is_directory {
            return format!("{indent}{branch}{label}");
        }

        let size_text = format!("({})", self.ui.format_bytes(entry.size));
        let size_tag = if colors_enabled() {
            format!("  {}", size_text.dimmed())
        } else {
            format!("  {size_text}")
        };

        format!("{indent}{branch}{label}{size_tag}")
    }

    /// Print a line on stdout without clobbering the spinner on stderr.
    /// `ProgressBar::println` would write to the bar's draw target, so the
    /// bar is suspended instead to keep tree output pipeable.
    fn println(self, line: &str) {
        match self.spinner {
            Some(bar) if !bar.is_hidden() => bar.suspend(|| println!("{line}")),
            _ => println!("{line}"),
        }
    }
}

/// Print the tree under `path`, or under every drive when `path` is absent.
/// `max_depth` 0 means unlimited.
pub async fn tree<T>(
    client: &mut Client<T, Connected>,
    path: Option<String>,
    max_depth: u32,
    include_files: bool,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let max_depth = NonZeroU32::new(max_depth);
    let spinner = (!ui.no_progress && std::io::stderr().is_terminal()).then(walk_spinner);

    let roots: Vec<String> = match path {
        Some(path) => vec![remote_path::normalize_dir_path(&path)],
        None => client
            .run(DriveList)
            .await?
            .into_iter()
            .map(|drive| format!("{drive}:\\"))
            .collect(),
    };

    let walk = Walk {
        max_depth,
        include_files,
        ui,
        spinner: spinner.as_ref(),
    };
    let mut dir_count: u64 = 0;
    for root in roots {
        walk.run(client, root, &mut dir_count).await;
    }

    if let Some(bar) = spinner {
        bar.finish_and_clear();
    }
    eprintln!(
        "{} {} dir{}",
        ok_tag("walked"),
        dir_count,
        if dir_count == 1 { "" } else { "s" }
    );

    Ok(())
}

fn walk_spinner() -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    bar.set_draw_target(ProgressDrawTarget::stderr());
    bar.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {prefix:.bold} dirs={msg}")
            .expect("valid spinner template"),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    bar.set_prefix("walking");

    bar
}

fn dir_label(name: &str, is_directory: bool) -> String {
    if !colors_enabled() || !is_directory {
        return name.to_owned();
    }

    format!("{}", name.blue().bold())
}

fn tree_indent(ancestors: &[bool], ui: UiOptions) -> String {
    let continuing = if ui.is_pretty() {
        "\u{2502}   "
    } else {
        "|   "
    };

    let mut indent = String::new();
    for &is_last in ancestors {
        indent.push_str(if is_last { "    " } else { continuing });
    }

    indent
}
