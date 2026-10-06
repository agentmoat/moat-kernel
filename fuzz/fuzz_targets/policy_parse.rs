//! Any policy file: loading, linting, warnings and compiling must report
//! errors, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moat_core::{CompiledPolicy, EvalContext, Policy, lint};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(policy) = Policy::parse(text) else {
        return;
    };
    let _ = lint::warnings(&policy);
    let ctx = EvalContext {
        home: "/home/me".into(),
        project: Some("/home/me/p".into()),
        cwd: "/home/me/p".into(),
        case_insensitive_paths: true,
        real_home: None,
        real_project: None,
    };
    let _ = CompiledPolicy::compile(&policy, &ctx);
});
