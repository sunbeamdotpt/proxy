// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

/// Spawn a new process with `--upgrade`, then send SIGQUIT to self.
///
/// Pingora's SIGQUIT handler transfers all listening socket FDs to the new
/// process via a Unix socket and begins draining existing connections.  The
/// new process calls `Server::new(Some(Opt { upgrade: true }))` in
/// `bootstrap()`, inherits the FDs, and takes over without dropping
/// connections.
///
/// When `SUNBEAM_DISABLE_GRACEFUL_UPGRADE` is set to any non-empty value,
/// this function returns immediately.  This is useful in environments where
/// the upgrade handshake cannot complete reliably (e.g. some conformance-test
/// containers) and a simple Pod restart is preferable to a stuck graceful
/// shutdown.
pub fn trigger_upgrade() {
    if std::env::var_os("SUNBEAM_DISABLE_GRACEFUL_UPGRADE").is_some() {
        tracing::info!("graceful upgrade disabled by SUNBEAM_DISABLE_GRACEFUL_UPGRADE");
        return;
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "cannot resolve current exe; upgrade aborted");
            return;
        }
    };

    match std::process::Command::new(&exe)
        .args(["serve", "--upgrade"])
        .spawn()
    {
        Ok(child) => tracing::info!(pid = child.id(), "upgrade process spawned"),
        Err(e) => {
            tracing::error!(error = %e, "failed to spawn upgrade process; upgrade aborted");
            return;
        }
    }

    // SAFETY: kill(getpid(), SIGQUIT) is always safe; we're only signalling ourselves.
    unsafe { libc::kill(libc::getpid(), libc::SIGQUIT) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_upgrade_returns_when_disabled() {
        // SAFETY: test-only mutation of an env var that no other test uses.
        unsafe { std::env::set_var("SUNBEAM_DISABLE_GRACEFUL_UPGRADE", "1") };
        trigger_upgrade();
        // Cleanup so other tests are not affected.
        unsafe { std::env::remove_var("SUNBEAM_DISABLE_GRACEFUL_UPGRADE") };
    }
}
