use anyhow::Result;
use crossterm::{
    cursor, execute,
    style::{Color, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use std::io::{stdout, Write};
use std::thread;
use std::time::Duration;

const RANDOM_CHARS: &[char] = &['%', '#', '$', '@', ')', '!', '^', '&', '*', '~', '+', '='];
const FRAME_COUNT: usize = 8;
const FRAME_DURATION_MS: u64 = 100; // ~800ms total for 8 frames

/// Display the welcome animation with morphing characters
/// Morphs from: base64 JWT -> random chars -> JSON array
pub fn show_welcome_animation() -> Result<()> {
    let mut stdout = stdout();

    // Sample JWT token (base64 encoded)
    let base64_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // Final target: one-line JSON array of decoded JWT
    let json_output = r#"[{"alg":"HS256","typ":"JWT"},{"sub":"1234567890","name":"John Doe","iat":1516239022,"msg":"Welcome to Jetta!"}]"#;

    // Hide cursor during animation
    execute!(stdout, cursor::Hide)?;

    // Run animation frames
    for frame_idx in 0..FRAME_COUNT {
        // Clear screen and move to top
        execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0))?;

        // Calculate morphing progress (0.0 to 1.0)
        let progress = frame_idx as f32 / (FRAME_COUNT - 1) as f32;

        // Morph from base64 to JSON through random chars
        let morphed_line = morph_jwt_line(base64_token, json_output, progress);
        writeln!(stdout, "{}", morphed_line)?;

        stdout.flush()?;

        // Don't sleep after last frame
        if frame_idx < FRAME_COUNT - 1 {
            thread::sleep(Duration::from_millis(FRAME_DURATION_MS));
        }
    }

    // Show cursor again
    execute!(stdout, cursor::Show)?;

    Ok(())
}

/// Morph a line from base64 JWT to JSON through random characters
/// Progress 0.0-0.5: base64 -> random chars
/// Progress 0.5-1.0: random chars -> JSON
fn morph_jwt_line(base64: &str, json: &str, progress: f32) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Determine which phase we're in
    let mut result = String::new();

    if progress < 0.5 {
        // Phase 1: base64 -> random chars (progress 0.0 to 0.5)
        let phase_progress = progress * 2.0; // Scale to 0.0-1.0

        for (idx, ch) in base64.chars().enumerate() {
            let reveal_threshold =
                1.0 - ((idx as f32 / base64.len().max(1) as f32) * 0.7 + 0.3 * phase_progress);

            if phase_progress >= reveal_threshold {
                // Morph to random character
                let random_char = RANDOM_CHARS[rng.gen_range(0..RANDOM_CHARS.len())];
                result.push(random_char);
            } else {
                // Still showing base64
                result.push(ch);
            }
        }

        // Colorize the random chars
        colorize_random_chars(&result)
    } else {
        // Phase 2: random chars -> JSON (progress 0.5 to 1.0)
        let phase_progress = (progress - 0.5) * 2.0; // Scale to 0.0-1.0

        for (idx, ch) in json.chars().enumerate() {
            let reveal_threshold =
                (idx as f32 / json.len().max(1) as f32) * 0.7 + 0.3 * phase_progress;

            if phase_progress >= reveal_threshold {
                // Reveal JSON character
                result.push(ch);
            } else if ch.is_whitespace() {
                result.push(ch);
            } else {
                // Show random character
                let random_char = RANDOM_CHARS[rng.gen_range(0..RANDOM_CHARS.len())];
                result.push(random_char);
            }
        }

        // Only colorize in early part of phase 2
        if phase_progress < 0.6 {
            colorize_random_chars(&result)
        } else {
            result
        }
    }
}

/// Add random colors to special characters in the string
fn colorize_random_chars(text: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut result = String::new();
    let colors = [
        Color::Red,
        Color::Green,
        Color::Yellow,
        Color::Blue,
        Color::Magenta,
        Color::Cyan,
    ];

    for ch in text.chars() {
        if RANDOM_CHARS.contains(&ch) {
            let color = colors[rng.gen_range(0..colors.len())];
            result.push_str(&format!(
                "{}{}{}",
                SetForegroundColor(color),
                ch,
                ResetColor
            ));
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_morph_jwt_line_phases() {
        let base64 = "eyJhbGciOiJIUzI1NiJ9";
        let json = r#"{"alg":"HS256"}"#;

        // At 0% progress, should show base64
        let result_start = morph_jwt_line(base64, json, 0.0);
        let clean_start = strip_ansi_codes(&result_start);
        assert_eq!(clean_start, base64);

        // At 50% progress, should have random chars
        let result_mid = morph_jwt_line(base64, json, 0.5);
        assert!(!result_mid.is_empty());

        // At 100% progress, should show JSON
        let result_end = morph_jwt_line(base64, json, 1.0);
        let clean_end = strip_ansi_codes(&result_end);
        assert_eq!(clean_end, json);
    }

    /// Helper to strip ANSI escape codes from a string
    fn strip_ansi_codes(text: &str) -> String {
        let mut result = String::new();
        let mut in_escape = false;

        for ch in text.chars() {
            if ch == '\x1b' {
                in_escape = true;
            } else if in_escape && ch == 'm' {
                in_escape = false;
            } else if !in_escape {
                result.push(ch);
            }
        }

        result
    }

    #[test]
    fn test_random_chars_constant() {
        assert!(!RANDOM_CHARS.is_empty());
        assert!(RANDOM_CHARS.contains(&'%'));
        assert!(RANDOM_CHARS.contains(&'#'));
    }
}
