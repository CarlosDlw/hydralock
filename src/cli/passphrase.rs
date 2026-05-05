use std::io::{self, IsTerminal};

/// Read a passphrase from TTY (if available) or stdin.
///
/// When stdin is a TTY, uses rpassword to hide echo. Otherwise reads a line
/// from stdin (useful for scripting/piped input).
pub fn read_passphrase(prompt: &str) -> anyhow::Result<Vec<u8>> {
    if io::stdin().is_terminal() {
        let pass = rpassword::prompt_password(prompt)?;
        Ok(pass.into_bytes())
    } else {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        // Strip trailing newline.
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line.into_bytes())
    }
}

/// Read and confirm a new passphrase (for encrypt/rewrap).
///
/// Prompts twice and requires both entries to match.
pub fn read_new_passphrase() -> anyhow::Result<Vec<u8>> {
    if io::stdin().is_terminal() {
        let pass = rpassword::prompt_password("Passphrase: ")?;
        let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
        if pass != confirm {
            anyhow::bail!("passphrases do not match");
        }
        Ok(pass.into_bytes())
    } else {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line.into_bytes())
    }
}
