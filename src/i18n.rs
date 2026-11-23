//! Language detection and runtime localization for Sekeeper (English default,
//! Italian when detected from the environment or selected explicitly).

use std::sync::atomic::{AtomicU8, Ordering};

const UNSET: u8 = 0;
const LANG_EN: u8 = 1;
const LANG_IT: u8 = 2;

static CURRENT_LANG: AtomicU8 = AtomicU8::new(UNSET);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    It,
}

impl Lang {
    /// Parses a BCP-47 or POSIX locale tag into a supported language.
    ///
    /// Returns [`Lang::It`] when the trimmed, ASCII-lowercased tag is `"it"` or
    /// starts with `"it_"`, `"it-"`, `"it."`, or `"it@"`, and [`Lang::En`]
    /// otherwise.
    pub fn from_tag(tag: &str) -> Self {
        let trimmed = tag.trim();
        if trimmed.eq_ignore_ascii_case("it") {
            return Self::It;
        }
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3
            && bytes[..2].eq_ignore_ascii_case(b"it")
            && matches!(bytes[2], b'_' | b'-' | b'.' | b'@')
        {
            Self::It
        } else {
            Self::En
        }
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

fn is_c_or_posix(value: &str) -> bool {
    matches!(value, "C" | "POSIX")
}

/// Pure helper implementing POSIX locale precedence:
/// `LC_ALL` > `LC_MESSAGES` > `LANGUAGE` (ignored when `LC_ALL` or `LANG` is
/// `"C"` or `"POSIX"`, inspecting the first non-empty `:`-separated entry) >
/// `LANG`, falling back to [`Lang::En`].
pub fn detect_from_values(
    lc_all: Option<&str>,
    lc_messages: Option<&str>,
    language: Option<&str>,
    lang: Option<&str>,
) -> Lang {
    if let Some(value) = non_empty(lc_all) {
        return Lang::from_tag(value);
    }
    if let Some(value) = non_empty(lc_messages) {
        return Lang::from_tag(value);
    }
    let lang_value = non_empty(lang);
    let lang_is_c = lang_value.is_some_and(is_c_or_posix);
    if !lang_is_c
        && let Some(value) = non_empty(language)
        && let Some(first) = value.split(':').map(str::trim).find(|s| !s.is_empty())
    {
        return Lang::from_tag(first);
    }
    if let Some(value) = lang_value {
        return Lang::from_tag(value);
    }
    Lang::En
}

/// Detects the active language from process environment variables following
/// POSIX precedence (`LC_ALL` > `LC_MESSAGES` > `LANGUAGE` > `LANG`).
pub fn detect_from_env() -> Lang {
    let lc_all = std::env::var("LC_ALL").ok();
    let lc_messages = std::env::var("LC_MESSAGES").ok();
    let language = std::env::var("LANGUAGE").ok();
    let lang = std::env::var("LANG").ok();
    detect_from_values(
        lc_all.as_deref(),
        lc_messages.as_deref(),
        language.as_deref(),
        lang.as_deref(),
    )
}

fn encode(lang: Lang) -> u8 {
    match lang {
        Lang::En => LANG_EN,
        Lang::It => LANG_IT,
    }
}

/// Sets the process-wide language explicitly.
pub fn set_lang(lang: Lang) {
    CURRENT_LANG.store(encode(lang), Ordering::Relaxed);
}

/// Returns the current process-wide language, initializing it from the
/// environment on first use if [`set_lang`] has not been called yet.
pub fn current_lang() -> Lang {
    match CURRENT_LANG.load(Ordering::Relaxed) {
        LANG_EN => Lang::En,
        LANG_IT => Lang::It,
        _ => {
            let detected = detect_from_env();
            let _ = CURRENT_LANG.compare_exchange(
                UNSET,
                encode(detected),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            match CURRENT_LANG.load(Ordering::Relaxed) {
                LANG_IT => Lang::It,
                _ => Lang::En,
            }
        }
    }
}

/// Returns `true` when the active language is Italian.
pub fn is_italian() -> bool {
    current_lang() == Lang::It
}

/// Selects the English or Italian string according to [`current_lang`].
pub fn tr(en: &'static str, it: &'static str) -> &'static str {
    match current_lang() {
        Lang::En => en,
        Lang::It => it,
    }
}

#[cfg(test)]
pub(crate) fn with_lang<R>(lang: Lang, f: impl FnOnce() -> R) -> R {
    use std::sync::Mutex;

    static TEST_LANG_LOCK: Mutex<()> = Mutex::new(());

    let _guard = TEST_LANG_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = CURRENT_LANG.swap(encode(lang), Ordering::Relaxed);
    struct Restore(u8);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT_LANG.store(self.0, Ordering::Relaxed);
        }
    }
    let _restore = Restore(previous);
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_tag_recognizes_italian_and_falls_back_to_english() {
        for tag in [
            "it",
            "IT",
            "  it  ",
            "it_IT",
            "it_IT.UTF-8",
            "it-IT",
            "it-CH",
            "IT_CH.UTF-8",
            "it.UTF-8",
            "it@euro",
        ] {
            assert_eq!(Lang::from_tag(tag), Lang::It, "tag: {tag}");
        }
        for tag in [
            "",
            "   ",
            "C",
            "POSIX",
            "en",
            "en_US.UTF-8",
            "en-GB",
            "fr_FR.UTF-8",
            "de_DE",
            "italian",
            "ita",
            "i",
        ] {
            assert_eq!(Lang::from_tag(tag), Lang::En, "tag: {tag}");
        }
    }

    #[test]
    fn detect_from_values_follows_posix_precedence() {
        // Fallback when everything is unset or empty.
        assert_eq!(detect_from_values(None, None, None, None), Lang::En);
        assert_eq!(
            detect_from_values(Some(""), Some("  "), Some(""), Some("")),
            Lang::En
        );

        // LANG alone.
        assert_eq!(
            detect_from_values(None, None, None, Some("it_IT.UTF-8")),
            Lang::It
        );
        assert_eq!(
            detect_from_values(None, None, None, Some("en_US.UTF-8")),
            Lang::En
        );

        // LC_ALL overrides everything, including C/POSIX.
        assert_eq!(
            detect_from_values(
                Some("it_IT.UTF-8"),
                Some("en_US.UTF-8"),
                Some("en:fr"),
                Some("en_US.UTF-8")
            ),
            Lang::It
        );
        assert_eq!(
            detect_from_values(
                Some("en_US.UTF-8"),
                Some("it_IT.UTF-8"),
                Some("it:en"),
                Some("it_IT.UTF-8")
            ),
            Lang::En
        );
        assert_eq!(
            detect_from_values(Some("C"), Some("it_IT"), Some("it:en"), Some("it_IT")),
            Lang::En
        );
        assert_eq!(
            detect_from_values(Some("POSIX"), Some("it_IT"), Some("it:en"), Some("it_IT")),
            Lang::En
        );

        // LC_MESSAGES overrides LANGUAGE and LANG when LC_ALL is unset/empty.
        assert_eq!(
            detect_from_values(
                Some(""),
                Some("it_CH.UTF-8"),
                Some("en:de"),
                Some("en_US.UTF-8")
            ),
            Lang::It
        );
        assert_eq!(
            detect_from_values(None, Some("en_US"), Some("it:en"), Some("it_IT")),
            Lang::En
        );
        assert_eq!(
            detect_from_values(None, Some("C"), Some("it:en"), Some("it_IT")),
            Lang::En
        );

        // LANGUAGE inspects the first non-empty ':'-separated entry.
        assert_eq!(
            detect_from_values(None, None, Some("it:en"), Some("en_US.UTF-8")),
            Lang::It
        );
        assert_eq!(
            detect_from_values(None, None, Some("::it_IT:en"), Some("en_US.UTF-8")),
            Lang::It
        );
        assert_eq!(
            detect_from_values(None, None, Some("en:it"), Some("it_IT.UTF-8")),
            Lang::En
        );
        assert_eq!(
            detect_from_values(None, None, Some("fr:it"), Some("it_IT.UTF-8")),
            Lang::En
        );
        // Empty LANGUAGE entries fall through to LANG.
        assert_eq!(
            detect_from_values(None, None, Some(":::"), Some("it_IT.UTF-8")),
            Lang::It
        );

        // LANGUAGE is ignored when LANG is C or POSIX.
        assert_eq!(
            detect_from_values(None, None, Some("it:en"), Some("C")),
            Lang::En
        );
        assert_eq!(
            detect_from_values(None, None, Some("it:en"), Some("POSIX")),
            Lang::En
        );
    }

    #[test]
    fn tr_and_state_switch_between_english_and_italian() {
        with_lang(Lang::En, || {
            assert_eq!(current_lang(), Lang::En);
            assert!(!is_italian());
            assert_eq!(tr("hello", "ciao"), "hello");
        });
        with_lang(Lang::It, || {
            assert_eq!(current_lang(), Lang::It);
            assert!(is_italian());
            assert_eq!(tr("hello", "ciao"), "ciao");
        });
    }
}
