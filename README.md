# Intelligit

> Intelligit is a tool for finding insight in git history. Intelligit is not an alternative to git but an addition.

![License](https://img.shields.io/crates/l/intelligit.svg)
[![Crates Status](https://img.shields.io/crates/v/intelligit.svg)](https://crates.io/crates/intelligit)

## How does it work
Intelligit uses [patterns](docs/PATTERNS.md) to find meaningful symbols in the source code and tracks changes in the symbols.
The patterns use [tree-sitter](https://github.com/tree-sitter/tree-sitter).

todo: Better explanation

## Installing

Using a pattern requires having the tree-sitter parser compiled. Intelligit will clone and compile the tree-sitter parser but requires that a c compiler is installed.

todo: Actual install steps

## Project Status
Intelligit is currently in its early stages of development, and the project's direction is open to exploration.


## Contributions
If you have an idea or want to help please do :)


## License
Intelligit is licensed under the [MIT License](LICENSE)


## Disclaimers
Some nighly features are currently used. To build you need nightly. These features should be removed (or postpone it long enough till the features are stable ;) ) 


## Acknowledgements
* [gitoxide](https://github.com/Byron/gitoxide)
