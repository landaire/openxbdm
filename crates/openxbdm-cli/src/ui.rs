//! Terminal output formatting: status tags, tables, and byte and time
//! rendering.

use std::io::IsTerminal;

use indicatif::ProgressBar;
use openxbdm_client::FileTime;
use owo_colors::OwoColorize;
use tabled::Table;
use tabled::Tabled;
use tabled::settings::Modify;
use tabled::settings::Style;
use tabled::settings::Width;
use tabled::settings::object::Rows;

use crate::args::OutputFormat;
use crate::progress;

/// Output settings shared by every subcommand.
#[derive(Debug, Clone, Copy)]
pub struct UiOptions {
    pub format: OutputFormat,
    pub no_progress: bool,
    pub raw_bytes: bool,
}

impl UiOptions {
    pub fn is_pretty(&self) -> bool {
        self.format == OutputFormat::Pretty
    }

    pub fn progress(&self, total: u64, label: &str) -> ProgressBar {
        progress::transfer_bar(total, label, self.no_progress)
    }

    pub fn format_bytes(&self, count: u64) -> String {
        if self.raw_bytes {
            return count.to_string();
        }

        humanize_bytes(count)
    }

    /// Render a `FileTime` as local time ("2026-04-20 15:42:10"), or as the
    /// raw FILETIME hex when it is outside jiff's representable range.
    pub fn format_time(&self, time: FileTime) -> String {
        match time.into_jiff_timestamp() {
            Ok(timestamp) => timestamp
                .to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string(),
            Err(_) => format!("{:#018x}", time.as_raw()),
        }
    }

    /// Table heading, colored in pretty mode.
    pub fn heading(&self, label: &str) -> String {
        if self.is_pretty() && colors_enabled() {
            return format!("{}", label.cyan().bold());
        }

        label.to_owned()
    }
}

pub fn humanize_bytes(count: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

    if count < 1024 {
        return format!("{count} B");
    }

    let mut value = count as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    format!("{value:.2} {}", UNITS[unit])
}

pub fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

/// Status tag for a completed step.
pub fn ok_tag(label: &str) -> String {
    if colors_enabled() {
        return format!("{}", label.green().bold());
    }

    label.to_owned()
}

/// Status tag for a warning.
pub fn warn_tag(label: &str) -> String {
    if colors_enabled() {
        return format!("{}", label.yellow().bold());
    }

    label.to_owned()
}

/// Print `rows` as a boxed table below `heading`.
pub fn print_table<I, T>(heading: &str, rows: I)
where
    I: IntoIterator<Item = T>,
    T: Tabled,
{
    if !heading.is_empty() {
        println!("{heading}");
    }

    let mut table = Table::new(rows);
    table
        .with(Style::rounded())
        .with(Modify::new(Rows::first()).with(Width::wrap(48)));
    println!("{table}");
}
