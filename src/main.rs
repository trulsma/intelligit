mod cli;
mod datastore;
mod diff;
mod git;
mod parser;

fn main() -> anyhow::Result<()> {
    crate::cli::main_impl()
}
