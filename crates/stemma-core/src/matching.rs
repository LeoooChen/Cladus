//! Case-insensitive pattern matching used by rules.
//!
//! Inputs are folded once with [`fold`] (patterns when the rule set is
//! compiled, process attributes when they are first read), so matching itself
//! never allocates.

/// Folds a string for case-insensitive comparison.
pub fn fold(s: &str) -> String {
    s.to_lowercase()
}

/// Folds a path and normalizes `\` to `/` so that either separator matches.
pub fn fold_path(s: &str) -> String {
    fold(s).replace('\\', "/")
}

/// Wildcard match on folded strings: `*` matches any run of characters
/// (including none) and `?` matches exactly one character.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    // After a `*`: the pattern position following it, and the text position
    // it currently stands for. On a mismatch the `*` absorbs one more char.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    pi += 1;
                    star = Some((pi, ti));
                    continue;
                }
                b'?' => {
                    pi += 1;
                    ti += utf8_len(t[ti]);
                    continue;
                }
                b if b == t[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        }
        let Some((star_pi, star_ti)) = star else {
            return false;
        };
        let next = star_ti + utf8_len(t[star_ti]);
        pi = star_pi;
        ti = next;
        star = Some((star_pi, next));
    }
    p[pi..].iter().all(|&b| b == b'*')
}

/// Length of the UTF-8 sequence that starts with `lead`.
fn utf8_len(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// A rule's command-line condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CmdlinePattern {
    /// Every whitespace-separated keyword must occur somewhere, in any order.
    Keywords(Vec<String>),
    /// The pattern contains `*` or `?`: wildcard match on the whole line.
    Wildcard(String),
}

impl CmdlinePattern {
    /// `None` for an empty pattern, which places no condition.
    pub fn new(pattern: &str) -> Option<Self> {
        let folded = fold(pattern.trim());
        if folded.is_empty() {
            None
        } else if folded.contains(['*', '?']) {
            Some(Self::Wildcard(folded))
        } else {
            Some(Self::Keywords(folded.split_whitespace().map(str::to_owned).collect()))
        }
    }

    /// `cmdline` must be folded.
    pub fn matches(&self, cmdline: &str) -> bool {
        match self {
            Self::Keywords(words) => words.iter().all(|w| cmdline.contains(w.as_str())),
            Self::Wildcard(pattern) => wildcard_match(pattern, cmdline),
        }
    }
}

/// A rule's image-path condition: a directory/file prefix, or a wildcard
/// pattern when it contains `*` or `?`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathPattern {
    Prefix(String),
    Wildcard(String),
}

impl PathPattern {
    /// `None` for an empty pattern, which places no condition.
    pub fn new(pattern: &str) -> Option<Self> {
        let folded = fold_path(pattern.trim());
        if folded.is_empty() {
            None
        } else if folded.contains(['*', '?']) {
            Some(Self::Wildcard(folded))
        } else {
            Some(Self::Prefix(folded))
        }
    }

    /// `path` must be folded with [`fold_path`].
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Prefix(prefix) => path.starts_with(prefix.as_str()),
            Self::Wildcard(pattern) => wildcard_match(pattern, path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(pattern: &str, text: &str) -> bool {
        wildcard_match(&fold(pattern), &fold(text))
    }

    #[test]
    fn wildcard_basics() {
        assert!(glob("chrome.exe", "chrome.exe"));
        assert!(!glob("chrome.exe", "firefox.exe"));
        assert!(glob("chrome*", "chrome.exe"));
        assert!(glob("*chrome*", "google-chrome.exe"));
        assert!(glob("*.exe", "test.exe"));
        assert!(!glob("*.dll", "test.exe"));
        assert!(glob("?.exe", "a.exe"));
        assert!(!glob("?.exe", "ab.exe"));
        assert!(glob("*py*on*", "python.exe"));
        assert!(glob("c?r?.exe", "curl.exe"));
        assert!(!glob("c?r?.exe", "cargo.exe"));
    }

    #[test]
    fn wildcard_is_case_insensitive() {
        assert!(glob("Chrome.EXE", "chrome.exe"));
        assert!(glob("PYTHON*", "python3.11.exe"));
    }

    #[test]
    fn wildcard_empty_inputs() {
        assert!(glob("", ""));
        assert!(!glob("", "something"));
        assert!(!glob("something", ""));
        assert!(glob("*", ""));
    }

    #[test]
    fn wildcard_handles_multibyte_characters() {
        assert!(glob("?.exe", "é.exe"));
        assert!(glob("微信*", "微信.exe"));
        assert!(glob("*信.exe", "微信.exe"));
        assert!(!glob("é.exe", "è.exe"));
        assert!(glob("*é", "èé"));
        assert!(glob("ÄPP.EXE", "äpp.exe"));
    }

    #[test]
    fn cmdline_keyword_mode_is_order_independent() {
        let cmdline = fold(r"C:\Python\python.exe udp_client.py --port 8080");
        let matches = |p: &str| CmdlinePattern::new(p).unwrap().matches(&cmdline);
        assert!(matches("udp_client"));
        assert!(matches("udp_client 8080"));
        assert!(matches("8080 UDP_CLIENT"));
        assert!(!matches("udp_client 9090"));
    }

    #[test]
    fn cmdline_wildcard_mode_is_order_sensitive() {
        let matches = |p: &str, c: &str| CmdlinePattern::new(p).unwrap().matches(&fold(c));
        assert!(matches("*udp_client*", r"C:\Python\python.exe udp_client.py"));
        assert!(matches("*udp_client*8080*", "python.exe udp_client.py --port 8080"));
        assert!(!matches("*udp_client*8080*", "python.exe udp_client.py --port 9090"));
        assert!(!matches("*8080*udp_client*", "python.exe udp_client.py --port 8080"));
    }

    #[test]
    fn empty_patterns_place_no_condition() {
        assert_eq!(CmdlinePattern::new("  "), None);
        assert_eq!(PathPattern::new(""), None);
    }

    #[test]
    fn path_prefix_accepts_either_separator() {
        let pattern = PathPattern::new(r"C:\Python311\").unwrap();
        assert!(pattern.matches(&fold_path(r"c:\python311\python.exe")));
        assert!(pattern.matches(&fold_path("C:/Python311/Scripts/pip.exe")));
        assert!(!pattern.matches(&fold_path(r"C:\Python312\python.exe")));
    }

    #[test]
    fn path_wildcard() {
        let pattern = PathPattern::new(r"*\node_modules\*\node.exe").unwrap();
        assert!(pattern.matches(&fold_path(r"D:\app\node_modules\bin\node.exe")));
        assert!(!pattern.matches(&fold_path(r"D:\app\node.exe")));
    }
}
