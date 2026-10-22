//! Terminal progress bar for `scan` and `full`. The scanner only talks to the
//! `scan::Progress` trait; everything about drawing lives here.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::report::human_bytes;
use crate::scan::Progress;

const BAR_CELLS: usize = 20;
const DEFAULT_WIDTH: usize = 100;
const REDRAW_EVERY: Duration = Duration::from_millis(100);

/// True when a live bar makes sense: not `--json` and stderr is a terminal.
pub fn bar_enabled(json: bool) -> bool {
    !json && std::io::stderr().is_terminal()
}

/// `12340` -> `12.340`.
pub fn group_thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(c);
    }
    out
}

/// `38` -> `0:38`, `3725` -> `1:02:05`.
pub fn human_eta(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// Size with a pt-BR decimal comma (`3,2 GB`).
fn size_br(n: u64) -> String {
    human_bytes(n).replace('.', ",")
}

/// Keeps the tail of `s` (the file name matters most), at most `max` chars.
pub fn truncate_path(s: &str, max: usize) -> String {
    let len = s.chars().count();
    if len <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let tail: String = s.chars().skip(len - (max - 1)).collect();
    format!("…{tail}")
}

/// Whole percent, floored; 100 only when everything is done. With no bytes to
/// scan (empty files only), falls back to the file count, then to 100.
fn percent(files_done: usize, total_files: usize, bytes_done: u64, total_bytes: u64) -> u64 {
    let (done, total) = if total_bytes > 0 {
        (bytes_done.min(total_bytes) as u128, total_bytes as u128)
    } else if total_files > 0 {
        (files_done.min(total_files) as u128, total_files as u128)
    } else {
        return 100;
    };
    (done * 100 / total) as u64
}

/// One progress line, at most `width` chars:
/// `[████░░] 61% · 12.340/20.100 arq · 3,2 GB/5,1 GB · 48 MB/s · ETA 0:38 · path`
pub fn render_line(
    files_done: usize,
    total_files: usize,
    bytes_done: u64,
    total_bytes: u64,
    throughput_bps: f64,
    current: &Path,
    width: usize,
) -> String {
    let pct = percent(files_done, total_files, bytes_done, total_bytes);
    let filled = (pct as usize * BAR_CELLS / 100).min(BAR_CELLS);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(BAR_CELLS - filled));
    let remaining = total_bytes.saturating_sub(bytes_done);
    let eta = if remaining == 0 && (total_bytes > 0 || files_done >= total_files) {
        human_eta(0)
    } else if throughput_bps > 0.0 && total_bytes > 0 {
        human_eta((remaining as f64 / throughput_bps).ceil() as u64)
    } else {
        "--:--".to_string()
    };
    let stats = format!(
        "[{bar}] {pct}% · {}/{} arq · {}/{} · {}/s · ETA {eta}",
        group_thousands(files_done),
        group_thousands(total_files),
        size_br(bytes_done),
        size_br(total_bytes),
        size_br(throughput_bps as u64),
    );
    let used = stats.chars().count();
    // " · " separator plus at least a few chars of path, else drop the path.
    let line = if width > used + 3 + 8 {
        let path = truncate_path(&current.display().to_string(), width - used - 3);
        format!("{stats} · {path}")
    } else {
        stats
    };
    truncate_path_end(&line, width)
}

fn truncate_path_end(s: &str, width: usize) -> String {
    s.chars().take(width).collect()
}

fn term_width() -> usize {
    // COLUMNS is only set by some shells; the fixed cap is the fallback.
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse::<usize>().ok())
        .filter(|&c| c > 20)
        .map_or(DEFAULT_WIDTH, |c| (c - 1).min(DEFAULT_WIDTH))
}

struct State {
    out: Box<dyn Write + Send>,
    interval: Duration,
    width: usize,
    started: Option<Instant>,
    last_draw: Option<Instant>,
    total_files: usize,
    total_bytes: u64,
    last_files: usize,
    last_bytes: u64,
    /// Chars on screen, so a shorter redraw can blank the leftovers.
    last_len: usize,
}

impl State {
    fn draw(&mut self, line: &str) {
        let len = line.chars().count();
        let pad = self.last_len.saturating_sub(len);
        // Progress output must never fail the scan: ignore write errors.
        let _ = write!(self.out, "\r{line}{}", " ".repeat(pad));
        let _ = self.out.flush();
        self.last_len = len;
    }

    fn due(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last_draw
            .is_some_and(|t| now.duration_since(t) < self.interval)
        {
            return false;
        }
        self.last_draw = Some(now);
        true
    }

    fn clear(&mut self) {
        if self.last_len > 0 {
            let _ = write!(self.out, "\r{}\r", " ".repeat(self.last_len));
            let _ = self.out.flush();
            self.last_len = 0;
        }
    }
}

/// Live single-line bar on stderr, redrawn at most every 100 ms.
pub struct TerminalProgress {
    state: Mutex<State>,
}

impl TerminalProgress {
    pub fn new() -> Self {
        Self::with_writer(Box::new(std::io::stderr()), REDRAW_EVERY, term_width())
    }

    fn with_writer(out: Box<dyn Write + Send>, interval: Duration, width: usize) -> Self {
        Self {
            state: Mutex::new(State {
                out,
                interval,
                width,
                started: None,
                last_draw: None,
                total_files: 0,
                total_bytes: 0,
                last_files: 0,
                last_bytes: 0,
                last_len: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Default for TerminalProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress for TerminalProgress {
    fn counting(&self, files_seen: usize) {
        let mut s = self.lock();
        if s.due() {
            let line = format!("contando arquivos… {}", group_thousands(files_seen));
            s.draw(&line);
        }
    }

    fn start(&self, total_files: usize, total_bytes: u64) {
        let mut s = self.lock();
        s.started = Some(Instant::now());
        s.last_draw = None;
        s.total_files = total_files;
        s.total_bytes = total_bytes;
    }

    fn advance(&self, files_done: usize, bytes_done: u64, current: &Path) {
        let mut s = self.lock();
        // Workers can report out of order; never move the bar backwards.
        s.last_files = s.last_files.max(files_done);
        s.last_bytes = s.last_bytes.max(bytes_done);
        if !s.due() {
            return;
        }
        let elapsed = s.started.map_or(0.0, |t| t.elapsed().as_secs_f64());
        let bps = if elapsed > 0.0 {
            s.last_bytes as f64 / elapsed
        } else {
            0.0
        };
        let line = render_line(
            s.last_files,
            s.total_files,
            s.last_bytes,
            s.total_bytes,
            bps,
            current,
            s.width,
        );
        s.draw(&line);
    }

    fn finish(&self) {
        self.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn line(fd: usize, tf: usize, bd: u64, tb: u64, bps: f64, p: &str, w: usize) -> String {
        render_line(fd, tf, bd, tb, bps, &PathBuf::from(p), w)
    }

    #[test]
    fn zero_percent() {
        let l = line(0, 10, 0, 1000, 0.0, "a.txt", 200);
        assert!(l.starts_with(&format!("[{}] 0% ", "░".repeat(20))), "{l}");
        assert!(l.contains("0/10 arq"));
        assert!(l.contains("ETA --:--"));
        assert!(l.ends_with("a.txt"));
    }

    #[test]
    fn mid_percent() {
        let gb = 1024u64 * 1024 * 1024;
        let l = line(
            12_340,
            20_100,
            3 * gb,
            5 * gb,
            48.0 * 1048576.0,
            "C:\\x.exe",
            200,
        );
        assert!(
            l.contains(&format!("[{}{}] 60% ", "█".repeat(12), "░".repeat(8))),
            "{l}"
        );
        assert!(l.contains("12.340/20.100 arq"), "{l}");
        assert!(l.contains("3,0 GB/5,0 GB"), "{l}");
        assert!(l.contains("48,0 MB/s"), "{l}");
        // 2 GB left at 48 MB/s = 2048/48 = 42.7 s -> 43 s.
        assert!(l.contains("ETA 0:43"), "{l}");
    }

    #[test]
    fn full_percent() {
        let l = line(5, 5, 1000, 1000, 100.0, "z", 200);
        assert!(l.contains(&format!("[{}] 100% ", "█".repeat(20))), "{l}");
        assert!(l.contains("ETA 0:00"));
    }

    #[test]
    fn not_100_until_done() {
        let l = line(9, 10, 999, 1000, 100.0, "z", 200);
        assert!(l.contains(" 99% "), "{l}");
    }

    #[test]
    fn zero_total_bytes_does_not_divide_by_zero() {
        // Only empty files: falls back to file counts.
        let l = line(1, 2, 0, 0, 0.0, "e", 200);
        assert!(l.contains(" 50% "), "{l}");
        let l = line(2, 2, 0, 0, 0.0, "e", 200);
        assert!(l.contains(" 100% ") && l.contains("ETA 0:00"), "{l}");
        // Nothing at all.
        let l = line(0, 0, 0, 0, 0.0, "", 200);
        assert!(l.contains(" 100% "), "{l}");
    }

    #[test]
    fn long_path_is_truncated_keeping_the_tail() {
        let long = format!("C:\\{}\\arquivo-final.exe", "pasta\\".repeat(30));
        let l = line(1, 10, 10, 100, 10.0, &long, 100);
        assert!(l.chars().count() <= 100, "{}", l.chars().count());
        assert!(l.contains('…'));
        assert!(l.ends_with("arquivo-final.exe"));
    }

    #[test]
    fn narrow_width_drops_path_and_never_overflows() {
        let l = line(1, 10, 10, 100, 10.0, "C:\\some\\file.exe", 60);
        assert!(l.chars().count() <= 60);
        assert!(!l.contains("file.exe"));
    }

    #[test]
    fn helpers() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1.000");
        assert_eq!(group_thousands(1_234_567), "1.234.567");
        assert_eq!(human_eta(0), "0:00");
        assert_eq!(human_eta(38), "0:38");
        assert_eq!(human_eta(600), "10:00");
        assert_eq!(human_eta(3725), "1:02:05");
        assert_eq!(truncate_path("abc", 5), "abc");
        assert_eq!(truncate_path("abcdef", 4), "…def");
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn text(b: &Buf) -> String {
        String::from_utf8(b.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn sink_draws_in_place_throttles_and_clears() {
        let buf = Buf::default();
        let p =
            TerminalProgress::with_writer(Box::new(buf.clone()), Duration::from_secs(3600), 100);
        p.start(2, 100);
        p.advance(1, 50, Path::new("a"));
        let first = text(&buf);
        assert!(first.starts_with('\r') && first.contains("50%"), "{first}");
        // Within the throttle window: nothing new is drawn.
        p.advance(2, 100, Path::new("b"));
        assert_eq!(text(&buf), first);
        p.finish();
        let all = text(&buf);
        let tail = &all[first.len()..];
        let drawn = first.trim_start_matches('\r').chars().count();
        assert_eq!(tail, format!("\r{}\r", " ".repeat(drawn)));
        // A second finish is a no-op.
        p.finish();
        assert_eq!(text(&buf), all);
    }

    #[test]
    fn sink_ignores_out_of_order_updates() {
        let buf = Buf::default();
        let p = TerminalProgress::with_writer(Box::new(buf.clone()), Duration::ZERO, 100);
        p.start(10, 100);
        p.advance(5, 80, Path::new("a"));
        p.advance(4, 60, Path::new("b"));
        assert!(text(&buf).rsplit('\r').next().unwrap().contains(" 80% "));
    }
}
