use std::{env, process::ExitCode, sync::Arc};

use lovelyres_electron_backend::{
    BackendState, DiagnosticLogCapture, DiagnosticLogLevel, parse_archive_root, serve,
};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> ExitCode {
    let diagnostic_capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
    let stderr_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(stderr_filter),
        )
        .with(diagnostic_capture.layer());
    if subscriber.try_init().is_err() {
        return ExitCode::FAILURE;
    }

    let archive_root = match parse_archive_root(env::args_os().skip(1)) {
        Ok(path) => path,
        Err(message) => {
            tracing::error!(error = message, "invalid backend command line");
            return ExitCode::from(2);
        }
    };
    let state = match BackendState::open_with_diagnostic_capture(archive_root, diagnostic_capture) {
        Ok(state) => Arc::new(state),
        Err(error) => {
            tracing::error!(error = %error, "failed to initialize the LovelyRes backend");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = serve(tokio::io::stdin(), tokio::io::stdout(), state).await {
        tracing::error!(error = %error, "backend protocol terminated unexpectedly");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
