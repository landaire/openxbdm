/// Why [`super::ClientEngine::submit`] was rejected. Returned synchronously
/// so the caller learns the misuse without waiting for the next `poll`.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// A previous command's response hasn't been pulled yet -- the
    /// engine doesn't pipeline.
    #[error("a command is already in flight; pull its response first")]
    CommandInFlight,
    /// Banner has not been read yet.
    #[error("banner not yet received; cannot submit commands")]
    NotConnected,
    /// Engine has terminally failed or the peer has closed.
    #[error("engine is no longer usable (closed or failed)")]
    Unusable,
    /// The connection is a notification channel and carries no commands.
    #[error("connection is a notification channel; commands are not accepted")]
    NotificationChannel,
}
