#[derive(Debug)]
pub(crate) struct Logger(());

const LOGGER: &Logger = &Logger(());

impl Logger {
    /// Create a new logger that logs to stderr and initialize it as the
    /// global logger. If there was a problem setting the logger, then an
    /// error is returned.
    pub fn init() -> Result<(), log::SetLoggerError> {
        log::set_logger(LOGGER)
    }
}

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        // We set the log level via log::set_max_level, so we don't need to
        // implement filtering here.
        true
    }

    // TODO: Simplifiy target. The part gets quite ugly
    fn log(&self, record: &log::Record<'_>) {
        match (record.file(), record.line()) {
            (Some(file), Some(line)) => {
                eprintln!(
                    "{}|{}|{}:{}: {}",
                    record.level(),
                    record.target(),
                    file,
                    line,
                    record.args()
                );
            }
            (Some(file), None) => {
                eprintln!(
                    "{}|{}|{}: {}",
                    record.level(),
                    record.target(),
                    file,
                    record.args()
                );
            }
            _ => {
                eprintln!("{}|{}: {}", record.level(), record.target(), record.args());
            }
        }
    }

    fn flush(&self) {
        // We use eprintln! which is flushed on every call.
    }
}
