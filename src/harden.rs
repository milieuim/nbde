//! Process-wide memory hygiene applied before any secret is handled.
//!
//! Per-buffer page protection is deliberately not used: secrets also live in
//! dependency internals (curve scalars, AES key schedules), which only a
//! process-wide `mlockall` covers.

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum HardenError {
    #[snafu(display("lock process memory"))]
    LockMemory { source: rustix::io::Errno },

    #[snafu(display("mark process non-dumpable"))]
    Dumpable { source: rustix::io::Errno },

    #[snafu(display("disable core dumps"))]
    CoreLimit { source: rustix::io::Errno },
}

/// Locks all current and future pages, forbids ptrace by same-uid processes
/// and core dumps. Any failure is fatal: the agent must not run unhardened.
pub fn harden_process() -> Result<(), HardenError> {
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).context(LockMemorySnafu)?;
    disable_dumps()
}

fn disable_dumps() -> Result<(), HardenError> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable).context(DumpableSnafu)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .context(CoreLimitSnafu)
}

#[cfg(test)]
mod tests {
    use super::*;

    // mlockall needs CAP_IPC_LOCK or a large RLIMIT_MEMLOCK, which test
    // sandboxes lack; it is covered by the VM test instead.
    #[test]
    fn dumps_can_be_disabled_without_privileges() {
        assert!(disable_dumps().is_ok());
        assert_eq!(
            rustix::process::dumpable_behavior().ok(),
            Some(DumpableBehavior::NotDumpable)
        );
    }
}
