//! Small helper module for CLI-side UI concerns: progress bars for
//! streaming transfers and tabular rendering for list commands.

use std::io::IsTerminal;
use std::time::Duration;

use indicatif::ProgressBar;
use indicatif::ProgressDrawTarget;
use indicatif::ProgressStyle;

/// Build a transfer progress bar suitable for streaming file I/O. If
/// `disabled` is true or stderr isn't a TTY the bar is hidden and its
/// `inc`/`finish` calls become no-ops.
pub fn transfer_bar(total: u64, label: &str, disabled: bool) -> ProgressBar {
    if disabled || !std::io::stderr().is_terminal() {
        return ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::hidden());
    }
    let bar = ProgressBar::new(total);
    bar.set_draw_target(ProgressDrawTarget::stderr());
    bar.set_style(
        ProgressStyle::with_template(
            "{prefix:.cyan.bold} [{bar:32.magenta/black}] {bytes:>9}/{total_bytes:<9}  {bytes_per_sec:>11}  eta {eta:>4}",
        )
        .expect("valid progress template")
        .progress_chars("##-"),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    bar.set_prefix(label.to_owned());
    bar
}

/// Standard boxed-table preset used by every pretty list command.
pub fn styled_table<I, T>(rows: I) -> String
where
    I: IntoIterator<Item = T>,
    T: tabled::Tabled,
{
    use tabled::settings::Modify;
    use tabled::settings::Style;
    use tabled::settings::Width;
    use tabled::settings::object::Rows;
    let mut table = tabled::Table::new(rows);
    table
        .with(Style::rounded())
        .with(Modify::new(Rows::first()).with(Width::wrap(48)));
    table.to_string()
}
