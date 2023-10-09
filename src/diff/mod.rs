use std::ops::Range;

/// Calculates all novel lines in before and after
pub fn diff(before: &[u8], after: &[u8]) -> (Vec<u32>, Vec<u32>) {
    let input = imara_diff::intern::InternedInput::new(before, after);

    let mut novel_lhs = vec![];
    let mut novel_rhs = vec![];

    let sink = |before: Range<u32>, after: Range<u32>| {
        novel_lhs.extend(before);
        novel_rhs.extend(after);
    };
    imara_diff::diff(imara_diff::Algorithm::Histogram, &input, sink);

    (novel_lhs, novel_rhs)
}

/// Get all [tree_sitter::InputEdit] needed to transform before to after, uses line based
/// diffing to calculate edits
pub fn changes(before: &[u8], after: &[u8]) -> Vec<tree_sitter::InputEdit> {
    let input = imara_diff::intern::InternedInput::new(before, after);

    let before_line_byte_positions: Vec<_> = std::iter::once(0)
        .chain(
            before
                .iter()
                .enumerate()
                .filter(|(_, &c)| c == b'\n')
                .map(|(idx, _)| idx + 1),
        )
        .chain(std::iter::once(before.len()))
        .collect();
    let after_line_byte_positions: Vec<_> = std::iter::once(0)
        .chain(
            after
                .iter()
                .enumerate()
                .filter(|(_, &c)| c == b'\n')
                .map(|(idx, _)| idx + 1),
        )
        .chain(std::iter::once(after.len()))
        .collect();

    fn line_to_byte_offset(line: usize, line_positions: &[usize]) -> usize {
        line_positions[line]
    }
    fn line_end_to_byte_offset(line: usize, line_positions: &[usize], data: &[u8]) -> usize {
        *line_positions
            .get(line + 1)
            .unwrap_or(&data.len().saturating_sub(1))
    }
    fn byte_offset_to_point(byte_offset: usize, line_positions: &[usize]) -> tree_sitter::Point {
        let row = byte_offset_to_line(byte_offset, line_positions);
        let column = byte_offset - line_to_byte_offset(row, line_positions);
        tree_sitter::Point { row, column }
    }
    fn byte_offset_to_line(byte_offset: usize, line_positions: &[usize]) -> usize {
        std::cmp::max(
            match line_positions.binary_search(&byte_offset) {
                Ok(idx) => idx,
                Err(idx) => idx.saturating_sub(1),
            },
            0,
        )
    }

    let mut changes = vec![];
    let mut byte_offset: i32 = 0;
    let sink = |before_lines: Range<u32>, after_lines: Range<u32>| {
        let start_byte =
            line_to_byte_offset(before_lines.start as usize, &before_line_byte_positions) as i32
                + byte_offset;

        let new_start_byte =
            line_to_byte_offset(after_lines.start as usize, &after_line_byte_positions) as i32;

        let old_end_byte = before_lines
            .last()
            .map(|line| {
                line_end_to_byte_offset(line as usize, &before_line_byte_positions, before) as i32
                    + byte_offset
            })
            .unwrap_or(start_byte);

        let new_end_byte = after_lines
            .last()
            .map(|line| {
                line_end_to_byte_offset(line as usize, &after_line_byte_positions, after) as i32
            })
            .unwrap_or(new_start_byte);

        changes.push(tree_sitter::InputEdit {
            start_byte: start_byte as usize,
            old_end_byte: old_end_byte as usize,
            new_end_byte: new_end_byte as usize,
            start_position: byte_offset_to_point(
                (start_byte - byte_offset) as usize,
                &before_line_byte_positions,
            ),
            old_end_position: byte_offset_to_point(
                (old_end_byte - byte_offset) as usize,
                &before_line_byte_positions,
            ),
            new_end_position: byte_offset_to_point(
                new_end_byte as usize,
                &after_line_byte_positions,
            ),
        });
        byte_offset -= old_end_byte - start_byte;
        byte_offset += new_end_byte - start_byte;
    };

    imara_diff::diff(imara_diff::Algorithm::Histogram, &input, sink);

    // diff works by line and causes problem when eof changes to/from newline
    if before.last() != after.last() {
        let (start_byte, old_end_byte, new_end_byte) = if before.last() == Some(&b'\n') {
            let start_byte = before.len() as i32 + byte_offset - 2;
            let old_end_byte = start_byte + 1;
            let new_end_byte = after.len() as i32 - 1;
            (start_byte, old_end_byte, new_end_byte)
        } else {
            let start_byte = before.len() as i32 + byte_offset - 1;
            let old_end_byte = start_byte;
            let new_end_byte = after.len() as i32 - 1;

            (start_byte, old_end_byte, new_end_byte)
        };
        changes.push(tree_sitter::InputEdit {
            start_byte: start_byte as usize,
            old_end_byte: old_end_byte as usize,
            new_end_byte: new_end_byte as usize,
            start_position: byte_offset_to_point(
                (start_byte - byte_offset) as usize,
                &before_line_byte_positions,
            ),
            old_end_position: byte_offset_to_point(
                (old_end_byte - byte_offset) as usize,
                &before_line_byte_positions,
            ),
            new_end_position: byte_offset_to_point(
                new_end_byte as usize,
                &after_line_byte_positions,
            ),
        });
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::{changes, diff};

    #[test]
    fn diff_returns_correct_lines() {
        let before = b"line 1\nline2\nline3";
        let after = b"line 1\nline2\nline3\nline4";

        assert_eq!(diff(before, after), (vec![], vec![3]));
        assert_eq!(diff(after, before), (vec![3], vec![]));
    }

    fn assert_tree_is_same_after_edits(
        language: tree_sitter::Language,
        before: &[u8],
        after: &[u8],
    ) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(language).unwrap();
        let mut before_tree = parser.parse(before, None).unwrap();

        let changes = changes(before, after);

        assert!(!changes.is_empty());
        for change in changes {
            before_tree.edit(&change);
        }

        let after_tree_without_edits = parser.parse(after, None).unwrap();
        let after_tree = parser.parse(after, Some(&before_tree)).unwrap();

        assert_eq!(
            after_tree.root_node().to_sexp(),
            after_tree_without_edits.root_node().to_sexp()
        );
        assert_eq!(
            after_tree.root_node().range(),
            after_tree_without_edits.root_node().range()
        );

        fn recurse<'a>(lhs: tree_sitter::Node<'a>, rhs: tree_sitter::Node<'a>) {
            let mut lhs_walker = lhs.walk();
            let lhs_children: Vec<_> = lhs.children(&mut lhs_walker).collect();
            let mut rhs_walker = rhs.walk();
            let rhs_children: Vec<_> = rhs.children(&mut rhs_walker).collect();
            assert_eq!(lhs_children.len(), rhs_children.len());

            assert_eq!(lhs.range(), rhs.range());

            for (lhs, rhs) in lhs_children.into_iter().zip(rhs_children) {
                recurse(lhs, rhs);
            }
        }

        recurse(after_tree.root_node(), after_tree_without_edits.root_node());
    }

    #[test]
    fn diff_works_with_tree_sitter_trees() {
        let rust = tree_sitter_rust::language();
        let toml = tree_sitter_toml::language();
        let before = b"fn main() {}";
        let after = b"fn not_main() {}";
        assert_tree_is_same_after_edits(rust, before, after);
        assert_tree_is_same_after_edits(rust, after, before);

        let before = b" fn main() { println!(\"hello\");
        }
        fn deleted_function() {

        }
        fn another_function() {

        }
        ";
        let after = b"fn main() {
            print_hello();
        }
        fn print_hello() {
            println!(\"hello\");
        }
        fn another_function() {

        }
        ";
        assert_tree_is_same_after_edits(rust, before, after);
        assert_tree_is_same_after_edits(rust, after, before);

        let before = b"

        fn main() {
            dbg!(\"x\");
            println!(\"hello\");
        }";
        let after = b"
        fn print_hello() {
            println!(\"hello\");
        }



        fn main() {
            dbg!(\"hello\");
        }


        fn another_function() {

        }";
        assert_tree_is_same_after_edits(rust, before, after);
        assert_tree_is_same_after_edits(rust, after, before);

        let before = include_bytes!("test/changed_files/main.before.rs");
        let after = include_bytes!("test/changed_files/main.after.rs");
        assert_tree_is_same_after_edits(rust, before, after);
        assert_tree_is_same_after_edits(rust, after, before);

        let before = include_bytes!("test/changed_files/before.toml");
        let after = include_bytes!("test/changed_files/after.toml");
        assert_tree_is_same_after_edits(toml, before, after);
        assert_tree_is_same_after_edits(toml, after, before);

        let before = include_bytes!("test/changed_files/before_2.toml");
        let after = include_bytes!("test/changed_files/after_2.toml");
        assert_tree_is_same_after_edits(toml, before, after);
        assert_tree_is_same_after_edits(toml, after, before);
    }
}
