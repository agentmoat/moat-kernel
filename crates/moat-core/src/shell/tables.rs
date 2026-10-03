//! Program and extension tables that drive classification.
//!
//! Keep these data-only. Behaviour belongs in `commands` and `tokens`.

pub const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// Programs whose first non-option argument is itself a command to run.
pub const WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "nohup",
    "time",
    "nice",
    "ionice",
    "xargs",
    "command",
    "exec",
    "builtin",
    "timeout",
    "watch",
    "caffeinate",
    "stdbuf",
    "chroot",
    "unbuffer",
];

/// Wrappers that take one positional value before the wrapped command.
pub const WRAPPERS_WITH_VALUE: &[&str] = &["timeout", "chroot"];

/// Wrapper options that consume the following argument (`sudo -u root …`).
pub const WRAPPER_OPTIONS_WITH_VALUE: &[(&str, &[&str])] = &[
    (
        "sudo",
        &["-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D"],
    ),
    ("doas", &["-u", "-C"]),
    ("env", &["-u", "-C", "-S", "--unset", "--chdir"]),
    ("nice", &["-n"]),
    ("ionice", &["-c", "-n", "-p"]),
    ("xargs", &["-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a"]),
    ("timeout", &["-s", "-k", "--signal", "--kill-after"]),
    ("watch", &["-n", "-d"]),
    ("stdbuf", &["-i", "-o", "-e"]),
    ("exec", &["-a"]),
];

pub const ENV_BUILTINS: &[&str] = &["export", "declare", "typeset", "local", "readonly", "set"];

pub const SOURCE_BUILTINS: &[&str] = &["source", "."];

/// Interpreters with an inline-code flag whose payload is scanned, not parsed as shell.
pub const INLINE_INTERPRETERS: &[(&str, &[&str])] = &[
    ("python", &["-c"]),
    ("python3", &["-c"]),
    ("node", &["-e", "--eval", "-p", "--print"]),
    ("deno", &["eval"]),
    ("bun", &["-e"]),
    ("perl", &["-e", "-E"]),
    ("ruby", &["-e"]),
    ("php", &["-r"]),
    ("osascript", &["-e"]),
    ("pwsh", &["-c", "-Command"]),
    ("powershell", &["-c", "-Command"]),
];

/// Programs for which every path argument is a write.
pub const WRITE_ALL_PATHS: &[&str] = &[
    "rm", "rmdir", "touch", "mkdir", "chmod", "chown", "chgrp", "truncate", "unlink", "shred",
    "tee", "install", "mkfifo", "mknod",
];

/// Programs for which the last operand is a write and the others are reads.
pub const WRITE_LAST_PATH: &[&str] = &["cp", "mv", "ln", "rsync", "scp"];

/// Special parameters that are not environment variables.
pub const SPECIAL_PARAMS: &[char] = &['?', '$', '!', '#', '@', '*', '-', '0'];

/// Variables that are expanded by the classifier itself or carry no secret.
pub const IGNORED_VARS: &[&str] = &["HOME", "PWD", "OLDPWD", "USER", "SHELL", "TERM", "project"];

/// Suffixes that make a dotted token a file name rather than a host.
pub const FILE_EXTENSIONS: &[&str] = &[
    "rs", "js", "ts", "tsx", "jsx", "mjs", "cjs", "py", "rb", "php", "go", "java", "kt", "swift",
    "c", "h", "cpp", "hpp", "cs", "md", "txt", "json", "yaml", "yml", "toml", "lock", "sh", "bash",
    "zsh", "html", "css", "scss", "vue", "svelte", "png", "jpg", "jpeg", "gif", "svg", "pdf",
    "zip", "tar", "gz", "tgz", "bz2", "xz", "log", "env", "cfg", "ini", "xml", "csv", "sql", "db",
    "sqlite", "wasm", "so", "dylib", "dll", "exe", "bin", "o", "a", "class", "jar", "war", "plist",
    "conf", "pem", "key", "crt",
];
