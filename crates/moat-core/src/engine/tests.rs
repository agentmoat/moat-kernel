use super::*;

fn ctx() -> EvalContext {
    EvalContext {
        home: "/h".into(),
        project: "/p".into(),
        cwd: "/p".into(),
    }
}

fn policy(yaml: &str) -> Policy {
    Policy::parse(yaml).expect("test policy must lint")
}

fn shell(command: &str) -> Action {
    Action::Shell {
        command: command.to_owned(),
    }
}

#[test]
fn deny_is_absolute_over_allow() {
    let p = policy(
        "version: 1\ndeny:\n  - id: d\n    shell: ['git push --force*']\n\
         allow:\n  - id: a\n    shell: ['git *']\n",
    );
    let d = evaluate(&p, &ctx(), &shell("git push --force")).unwrap();
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["d"]);
}

#[test]
fn strictest_atom_wins_and_weaker_matches_become_context() {
    let p = policy(
        "version: 1\ndeny:\n  - id: secret\n    fs.read: ['~/.ssh/**']\n\
         allow:\n  - id: cat\n    shell: ['cat *']\n",
    );
    let d = evaluate(&p, &ctx(), &shell("cat ~/.ssh/id_rsa")).unwrap();
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["secret"]);
    assert!(d.context.iter().any(|c| c.contains("cat")));
}

#[test]
fn per_kind_defaults_apply_with_synthetic_ids() {
    let p = policy("version: 1\ndefaults: { '*': allow, net: deny }\n");
    let d = evaluate(&p, &ctx(), &shell("curl https://example.org")).unwrap();
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["default.net"]);
    let d = evaluate(&p, &ctx(), &shell("ls")).unwrap();
    assert_eq!(d.verdict, Verdict::Allow);
    assert_eq!(d.rules, ["default"]);
}

#[test]
fn negated_allow_patterns_fall_through_to_default() {
    let p = policy(
        "version: 1\ndefaults: ask\nallow:\n  - id: proj\n    \
         fs.write: ['${project}/**', '!${project}/.git/**']\n",
    );
    let write = |path: &str| Action::FsWrite {
        path: path.to_owned(),
    };
    assert_eq!(
        evaluate(&p, &ctx(), &write("/p/src/a.rs")).unwrap().verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&p, &ctx(), &write("/p/.git/HEAD"))
            .unwrap()
            .verdict,
        Verdict::Ask
    );
}

#[test]
fn unparseable_is_never_allowed() {
    let p = policy("version: 1\ndefaults: allow\n");
    let d = evaluate(&p, &ctx(), &shell("echo 'unterminated")).unwrap();
    assert_eq!(d.verdict, Verdict::Ask);
    assert_eq!(d.rules, ["unparseable"]);
    let d = evaluate(
        &p,
        &ctx(),
        &Action::Net {
            url: "https://".into(),
        },
    )
    .unwrap();
    assert_eq!(d.verdict, Verdict::Ask);
}

#[test]
fn pinned_executables_are_enforced_through_the_resolver() {
    use crate::programs::MapResolver;
    use std::collections::BTreeMap;
    let p = policy("version: 1\ndefaults: allow\nexecutables:\n  git: ['/usr/bin/git']\n");
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let planted = MapResolver {
        resolved: BTreeMap::from([("git".to_owned(), "/p/.bin/git".to_owned())]),
        pins: BTreeMap::new(),
    };
    let d = compiled.decide_with(&shell("git status"), &planted, &NoResolver);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["executables"]);
    let genuine = MapResolver {
        resolved: BTreeMap::from([("git".to_owned(), "/usr/bin/git".to_owned())]),
        pins: BTreeMap::new(),
    };
    assert_eq!(
        compiled
            .decide_with(&shell("git status"), &genuine, &NoResolver)
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        compiled.decide(&shell("git status")).verdict,
        Verdict::Deny,
        "pinned but unresolvable"
    );
}

#[test]
fn symlinked_paths_are_checked_at_both_locations() {
    use crate::realpath::MapPathResolver;
    use std::collections::BTreeMap;
    let p = policy(
        "version: 1\ndefaults: ask\ndeny:\n  - id: secret\n    \
         fs.read: ['~/.ssh/**']\n    fs.write: ['~/.ssh/**']\n\
         allow:\n  - id: proj\n    fs.read: ['${project}/**']\n    \
         fs.write: ['${project}/**']\n  - id: cat\n    shell: ['cat *', 'echo *']\n",
    );
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let links = MapPathResolver {
        links: BTreeMap::from([
            ("/p/s".to_owned(), "/h/.ssh".to_owned()),
            ("/p/lib".to_owned(), "/p/vendor/lib".to_owned()),
        ]),
    };
    let decide = |a: &Action| compiled.decide_with(a, &NoResolver, &links);
    let d = decide(&shell("cat ./s/id_rsa"));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rules, ["secret"]);
    assert!(d.reasons.iter().any(|r| r.contains("/h/.ssh/id_rsa")));
    assert_eq!(
        decide(&shell("echo k >> s/authorized_keys")).verdict,
        Verdict::Deny
    );
    assert_eq!(
        decide(&Action::FsRead {
            path: "/p/s/config".into()
        })
        .verdict,
        Verdict::Deny
    );
    assert_eq!(decide(&shell("cat ./lib/a.rs")).verdict, Verdict::Allow);
    assert_eq!(
        compiled.decide(&shell("cat ./s/id_rsa")).verdict,
        Verdict::Allow,
        "without a resolver only the literal path is known"
    );
}

#[test]
fn patches_write_every_file_and_ask_when_empty() {
    let p = policy(
        "version: 1\ndefaults: ask\ndeny:\n  - id: rc\n    fs.write: ['~/.zshrc']\n\
         allow:\n  - id: proj\n    fs.write: ['${project}/**']\n",
    );
    let patch = |w: &[&str]| Action::Patch {
        writes: w.iter().map(|s| (*s).to_owned()).collect(),
    };
    let d = evaluate(&p, &ctx(), &patch(&["src/a.rs", "src/b.rs"])).unwrap();
    assert_eq!(d.verdict, Verdict::Allow);
    let d = evaluate(&p, &ctx(), &patch(&["src/a.rs", "~/.zshrc"])).unwrap();
    assert_eq!(
        (d.verdict, d.rules.as_slice()),
        (Verdict::Deny, &["rc".to_owned()][..])
    );
    let d = evaluate(&p, &ctx(), &patch(&[])).unwrap();
    assert_eq!(
        (d.verdict, d.rules.as_slice()),
        (Verdict::Ask, &["unparseable".to_owned()][..])
    );
}

#[test]
fn compiled_policy_is_reusable() {
    let p = policy("version: 1\ndefaults: ask\nallow:\n  - id: ls\n    shell: ['ls*']\n");
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    for _ in 0..3 {
        assert_eq!(compiled.decide(&shell("ls -la")).verdict, Verdict::Allow);
    }
}
