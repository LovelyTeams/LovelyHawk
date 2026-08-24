use lovelyres_terminal::{CellPosition, TerminalConfig, TerminalModel, TerminalSize};
use serde::Deserialize;

const FIXTURES: &[&str] = &[
    include_str!("fixtures/alternate_screen.json"),
    include_str!("fixtures/bracketed_paste.json"),
    include_str!("fixtures/wide_combining.json"),
    include_str!("fixtures/resize.json"),
];

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    initial_size: FixtureSize,
    steps: Vec<FixtureStep>,
    expected: FixtureExpected,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct FixtureSize {
    columns: u16,
    rows: u16,
}

impl FixtureSize {
    fn terminal_size(self) -> TerminalSize {
        TerminalSize::new(self.columns, self.rows).unwrap()
    }
}

#[derive(Debug, Deserialize)]
struct FixtureStep {
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    resize: Option<FixtureSize>,
    #[serde(default)]
    alternate_screen: Option<bool>,
    #[serde(default)]
    bracketed_paste: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    size: FixtureSize,
    visible_line_prefixes: Vec<String>,
    #[serde(default)]
    cells: Vec<ExpectedCell>,
    #[serde(default)]
    paste: Option<ExpectedPaste>,
}

#[derive(Debug, Deserialize)]
struct ExpectedCell {
    row: u16,
    column: u16,
    character: String,
    combining: String,
    wide: bool,
    wide_spacer: bool,
}

#[derive(Debug, Deserialize)]
struct ExpectedPaste {
    input: String,
    bytes: String,
}

#[test]
fn terminal_conformance_fixtures() {
    for source in FIXTURES {
        let fixture: Fixture = serde_json::from_str(source).unwrap();
        run_fixture(&fixture);
    }
}

fn run_fixture(fixture: &Fixture) {
    let config = TerminalConfig {
        size: fixture.initial_size.terminal_size(),
        ..Default::default()
    };
    let mut model = TerminalModel::new(config).unwrap();

    for step in &fixture.steps {
        if let Some(output) = &step.output {
            model.feed_output(output.as_bytes());
        }
        if let Some(size) = step.resize {
            model.resize(size.terminal_size()).unwrap();
        }
        if let Some(expected) = step.alternate_screen {
            assert_eq!(
                model.is_alternate_screen(),
                expected,
                "{} alternate-screen checkpoint",
                fixture.name
            );
        }
        if let Some(expected) = step.bracketed_paste {
            assert_eq!(
                model.is_bracketed_paste(),
                expected,
                "{} bracketed-paste checkpoint",
                fixture.name
            );
        }
    }

    assert_eq!(
        model.size(),
        fixture.expected.size.terminal_size(),
        "{} final size",
        fixture.name
    );
    let lines = model.viewport_lines();
    for (index, prefix) in fixture.expected.visible_line_prefixes.iter().enumerate() {
        assert!(
            lines
                .get(index)
                .is_some_and(|line| line.starts_with(prefix)),
            "{} viewport line {index}: expected prefix {prefix:?}, got {:?}",
            fixture.name,
            lines.get(index)
        );
    }
    for expected in &fixture.expected.cells {
        let cell = model
            .cell(CellPosition::new(expected.row, expected.column))
            .unwrap();
        let mut characters = expected.character.chars();
        assert_eq!(
            cell.character,
            characters.next().unwrap(),
            "{}",
            fixture.name
        );
        assert_eq!(
            characters.next(),
            None,
            "{} fixture character",
            fixture.name
        );
        assert_eq!(
            cell.combining,
            expected.combining.chars().collect::<Vec<_>>(),
            "{} combining marks",
            fixture.name
        );
        assert_eq!(cell.wide, expected.wide, "{} wide cell", fixture.name);
        assert_eq!(
            cell.wide_spacer, expected.wide_spacer,
            "{} wide spacer",
            fixture.name
        );
    }
    if let Some(expected) = &fixture.expected.paste {
        assert_eq!(
            model.paste_bytes(&expected.input),
            expected.bytes.as_bytes(),
            "{} paste encoding",
            fixture.name
        );
    }
}
