use std::io::{self, Write};

use anyhow::{Context, Result};
use kcart::config::LogFormat;
use log::{Level, LevelFilter, Log, Metadata, Record};

struct Logger {
    format: LogFormat,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = record.level().as_str().to_ascii_lowercase();
        let line = match self.format {
            LogFormat::Text => format!("{level} {}", record.args()),
            LogFormat::Json => serde_json::json!({
                "level": level,
                "msg": record.args().to_string(),
            })
            .to_string(),
        };
        // There is nowhere left to report a failing stderr.
        let _ = writeln!(io::stderr().lock(), "{line}");
    }

    fn flush(&self) {}
}

pub fn init(format: LogFormat) -> Result<()> {
    log::set_boxed_logger(Box::new(Logger { format })).context("installing the logger")?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}
