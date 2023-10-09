#![feature(hash_extract_if, extract_if)]
mod cli;
mod datastore;
mod diff;
mod git;
mod parser;

fn main() -> anyhow::Result<()> {
    crate::cli::main_impl()
}
