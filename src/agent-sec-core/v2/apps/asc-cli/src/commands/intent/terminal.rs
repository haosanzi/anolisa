//! Bounded terminal line input with state restoration; Enter, EOF and interrupts never imply approval.

use std::io::{self, Write as _};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};

use super::{IntentFailure, check_interrupt, render};

pub(super) struct Interrupt(signal_hook::SigId);
impl Interrupt {
    pub(super) fn register(flag: Arc<AtomicBool>) -> io::Result<Self> {
        signal_hook::flag::register(signal_hook::consts::SIGINT, flag).map(Self)
    }
}
impl Drop for Interrupt {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.0);
    }
}

struct RawMode;
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

pub(super) fn line(
    prompt: &str,
    limit: usize,
    interrupted: &AtomicBool,
) -> Result<Option<String>, IntentFailure> {
    terminal::enable_raw_mode()?;
    let raw = RawMode;
    let mut out = io::stdout().lock();
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut text = String::new();
    let result = loop {
        check_interrupt(interrupted)?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') => return Err(IntentFailure::Interrupted),
                KeyCode::Char('d') => break None,
                _ => continue,
            }
        }
        match key.code {
            KeyCode::Enter => break Some(text),
            KeyCode::Esc => break None,
            KeyCode::Backspace => {
                // Redraw the escaped line so invisible characters cannot spoof the prompt.
                if text.pop().is_some() {
                    write!(out, "\r\x1b[2K{prompt}{}", render::escape(&text))?;
                }
            }
            KeyCode::Char(ch) if !ch.is_control() => {
                if text.len() + ch.len_utf8() > limit {
                    return Err(IntentFailure::Limit);
                }
                text.push(ch);
                write!(out, "{}", render::escape(&ch.to_string()))?;
            }
            _ => {}
        }
        out.flush()?;
    };
    write!(out, "\r\n")?;
    out.flush()?;
    drop(raw);
    Ok(result)
}
