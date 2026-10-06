use super::*;

fn ctx() -> EvalContext {
    EvalContext {
        home: "/h".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        cwd: "/p".into(),
        case_insensitive_paths: false,
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
fn project_patterns_match_nothing_without_a_project() {
    let p = policy(
        "version: 1\ndefaults: ask\ndeny:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n\
         allow:\n  - id: proj\n    fs.read: ['${project}/**', '!${project}/.env']\n",
    );
    let read = |path: &str| Action::FsRead {
        path: path.to_owned(),
    };
    let home = EvalContext {
        project: None,
        cwd: "/h".into(),
        ..ctx()
    };
    for path in ["/h/notes.txt", "/.env", "/x"] {
        let d = evaluate(&p, &home, &read(path)).unwrap();
        assert_eq!(
            (d.verdict, d.rules),
            (Verdict::Ask, vec!["default".to_owned()]),
            "{path}"
        );
    }
    let d = evaluate(&p, &home, &shell("grep -r . ~/.ssh")).unwrap();
    assert_eq!(
        (d.verdict, d.rules),
        (Verdict::Deny, vec!["keys".to_owned()])
    );
    let d = evaluate(&p, &ctx(), &read("/p/notes.txt")).unwrap();
    assert_eq!(d.verdict, Verdict::Allow);
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
    let allowed = evaluate(&p, &ctx(), &write("/p/src/a.rs")).unwrap();
    assert_eq!(
        (allowed.verdict, allowed.rules),
        (Verdict::Allow, vec!["proj".to_owned()])
    );
    let excluded = evaluate(&p, &ctx(), &write("/p/.git/HEAD")).unwrap();
    assert_eq!(
        (excluded.verdict, excluded.rules),
        (Verdict::Ask, vec!["default".to_owned()]),
        "the exclusion falls through to the default, not to another rule"
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
    let powershell = Action::ForeignShell {
        shell: "PowerShell".into(),
        command: "Get-ChildItem".into(),
    };
    let d = evaluate(&p, &ctx(), &powershell).unwrap();
    assert_eq!(
        (d.verdict, d.rules),
        (Verdict::Ask, vec!["unparseable".to_owned()])
    );
}

/// An approval cannot make an unparseable command run: `sh -ee.a` has an option
/// cluster the shell grammar does not know, so even a literal allow of exactly
/// that command asks (found by the `literal_pattern` fuzz target).
#[test]
fn an_approved_unparseable_command_still_asks() {
    let pattern = crate::literal_shell_pattern("sh -ee.a").unwrap();
    let p = policy(&format!(
        "version: 1\ndefaults: deny\nallow:\n  - id: approved\n    shell: [\"{pattern}\"]\n"
    ));
    let d = evaluate(&p, &ctx(), &shell("sh -ee.a")).unwrap();
    assert_eq!(
        (d.verdict, d.rules),
        (Verdict::Ask, vec!["unparseable".to_owned()])
    );
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

#[test]
fn path_case_sensitivity_comes_from_the_context() {
    let p =
        policy("version: 1\ndefaults: allow\ndeny:\n  - id: secret\n    fs.read: ['~/.ssh/**']\n");
    let read = Action::FsRead {
        path: "/h/.SSH/id_rsa".into(),
    };
    let insensitive = EvalContext {
        case_insensitive_paths: true,
        ..ctx()
    };
    assert_eq!(
        evaluate(&p, &insensitive, &read).unwrap().verdict,
        Verdict::Deny
    );
    assert_eq!(evaluate(&p, &ctx(), &read).unwrap().verdict, Verdict::Allow);
}

/// Once `cd` is allowed, a relative read after it is checked where `cd` went,
/// and ordinary `cd … && build` lines keep the verdict they have without `cd`.
#[test]
fn reads_after_cd_are_checked_where_cd_went() {
    let p = policy(
        "version: 1\ndefaults: ask\ndeny:\n  - id: secret\n    fs.read: ['~/.ssh/**', '~/.aws/**']\n\
         allow:\n  - id: proj\n    fs.read: ['${project}/**']\n  - id: dev\n    \
         shell: ['cd *', 'cat *', 'head *', 'ls*', 'cargo test*']\n",
    );
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    for command in [
        "cd /h/.config && cat ../.ssh/id_rsa",
        "cd /h && cat .ssh/id_rsa",
        "cd /tmp; cd /h && head .aws/credentials",
    ] {
        let d = compiled.decide(&shell(command));
        assert_eq!(
            (d.verdict, d.rules),
            (Verdict::Deny, vec!["secret".to_owned()]),
            "{command}"
        );
    }
    for command in [
        "cd src && cargo test",
        "cd crates/x && ls",
        "cd src && cat main.rs",
    ] {
        assert_eq!(
            compiled.decide(&shell(command)).verdict,
            Verdict::Allow,
            "{command}"
        );
    }
    assert_eq!(
        compiled.decide(&shell("cd \"$DIR\" && cat id_rsa")).rules,
        ["unparseable"]
    );
}

fn fetch(url: &str) -> Action {
    Action::Fetch {
        url: url.to_owned(),
    }
}

fn verdict_and_rules(p: &Policy, action: &Action) -> (Verdict, Vec<String>) {
    let d = evaluate(p, &ctx(), action).unwrap();
    (d.verdict, d.rules)
}

#[test]
fn fetch_is_a_narrower_kind_of_net() {
    let p = policy(
        "version: 1\ndefaults: { net: deny, fetch: ask }\n\
         deny:\n  - id: metadata\n    net: ['169.254.169.254']\n\
         allow:\n  - id: registries\n    net: ['crates.io']\n  - id: docs\n    fetch: ['docs.rs']\n\
         ask:\n  - id: local\n    net: ['localhost']\n",
    );
    let cases = [
        (
            fetch("http://169.254.169.254/latest"),
            Verdict::Deny,
            "metadata",
        ),
        (fetch("https://CRATES.io/x"), Verdict::Allow, "registries"),
        (fetch("https://docs.rs/serde"), Verdict::Allow, "docs"),
        (fetch("http://localhost:3000/"), Verdict::Ask, "local"),
        (
            fetch("https://unknown.example/"),
            Verdict::Ask,
            "default.fetch",
        ),
        (
            shell("curl https://docs.rs/serde"),
            Verdict::Deny,
            "default.net",
        ),
        (
            shell("curl https://unknown.example/"),
            Verdict::Deny,
            "default.net",
        ),
    ];
    for (action, verdict, rule) in cases {
        let got = verdict_and_rules(&p, &action);
        assert_eq!(got, (verdict, vec![rule.to_owned()]), "{action:?}");
    }
}

#[test]
fn fetch_deny_list_never_catches_other_network_access() {
    let p = policy(
        "version: 1\ndefaults: allow\ndeny:\n  - id: no-fetch\n    fetch: ['*.example']\n\
         allow:\n  - id: also\n    fetch: ['a.example']\n",
    );
    assert_eq!(
        verdict_and_rules(&p, &fetch("https://a.example/")),
        (Verdict::Deny, vec!["no-fetch".to_owned()]),
        "deny stays absolute for fetches"
    );
    assert_eq!(
        verdict_and_rules(&p, &shell("curl https://a.example/")).0,
        Verdict::Allow
    );
}

#[test]
fn fetch_defaults_fall_back_to_net() {
    let p = policy("version: 1\ndefaults: { net: deny, '*': allow }\n");
    assert_eq!(
        verdict_and_rules(&p, &fetch("https://unknown.example/")),
        (Verdict::Deny, vec!["default.net".to_owned()])
    );
    let p = policy("version: 1\ndefaults: allow\n");
    assert_eq!(
        verdict_and_rules(&p, &fetch("https://")),
        (Verdict::Ask, vec!["unparseable".to_owned()])
    );
}

/// A project and home reached through links (macOS `/tmp` → `/private/tmp`)
/// are matched under both spellings, exclusions included; a link inside the
/// project is still checked where it points.
#[test]
fn roots_match_under_their_resolved_spelling_too() {
    use crate::realpath::MapPathResolver;

    let p = policy(
        "version: 1\ndefaults: ask\ndeny:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n\
         allow:\n  - id: proj\n    fs.read: ['${project}/**']\n\
         \x20   fs.write: ['${project}/**', '!${project}/.git/**']\n",
    );
    let linked = EvalContext {
        real_home: Some("/vol/h".into()),
        real_project: Some("/private/p".into()),
        ..ctx()
    };
    let links = MapPathResolver {
        links: [("/p", "/private/p"), ("/h", "/vol/h"), ("/p/e", "/etc")]
            .into_iter()
            .map(|(l, t)| (l.to_owned(), t.to_owned()))
            .collect(),
    };
    let compiled = CompiledPolicy::compile(&p, &linked).unwrap();
    let decide = |a: Action| {
        let d = compiled.decide_with(&a, &NoResolver, &links);
        (d.verdict, d.rules)
    };
    let read = |path: &str| Action::FsRead { path: path.into() };
    let write = |path: &str| Action::FsWrite { path: path.into() };
    let verdict = |v: Verdict, rule: &str| (v, vec![rule.to_owned()]);
    assert_eq!(decide(read("/p/a")), verdict(Verdict::Allow, "proj"));
    assert_eq!(
        decide(read("/private/p/a")),
        verdict(Verdict::Allow, "proj")
    );
    assert_eq!(
        decide(write("/private/p/a")),
        verdict(Verdict::Allow, "proj")
    );
    let git = verdict(Verdict::Ask, "default");
    assert_eq!(decide(write("/private/p/.git/config")), git);
    assert_eq!(decide(write("/p/.git/config")), git);
    let keys = verdict(Verdict::Deny, "keys");
    assert_eq!(decide(read("/vol/h/.ssh/id_rsa")), keys);
    assert_eq!(decide(read("/h/.ssh/id_rsa")), keys);
    assert_eq!(decide(read("/p/e/hosts")), verdict(Verdict::Ask, "default"));
    let unlinked = CompiledPolicy::compile(&p, &ctx()).unwrap();
    assert_eq!(
        unlinked.decide(&read("/private/p/a")).verdict,
        Verdict::Ask,
        "the resolved spelling is a fact the caller supplies"
    );
}

/// Matchers are built on first use, but a pattern that does not parse must
/// still fail the compile, before any decision, whichever kind it belongs to.
#[test]
fn a_pattern_broken_by_expansion_fails_the_compile_up_front() {
    let p = policy("version: 1\ndeny:\n  - id: secret\n    fs.read: ['~/.ssh/**']\n");
    let broken_home = EvalContext {
        home: "/h{x".into(),
        ..ctx()
    };
    assert!(matches!(
        CompiledPolicy::compile(&p, &broken_home),
        Err(PolicyError::BadGlob { .. })
    ));
}
