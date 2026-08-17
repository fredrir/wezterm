//! Native, fixed-path dmux service descriptor publication and verification.
//!
//! This module is deliberately narrower than a general filesystem API.  Lua
//! supplies only service metadata; runtime paths, process/boot identity, and
//! socket identity are derived here.  Publication and verification retain
//! directory/file descriptors and reject symlinks, loose modes, stale process
//! incarnations, and socket replacement.

use chrono::Utc;
use config::lua::mlua::{
    self, Lua, LuaSerdeExt, String as LuaString, Table, UserData, UserDataMethods,
    Value as LuaValue,
};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DESCRIPTOR_VERSION: u32 = 1;
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_RECOVERY_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_RECOVERY_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const RUNTIME_DIR: &str = "dmux";
const DESCRIPTOR_FILE: &str = "wez-dmux.json";
const SOCKET_FILE: &str = "wez-dmux.sock";
const SERVICE_LEASE_FILE: &str = ".wez-dmux-service.lease";

static SERVICE_BOOTSTRAP: OnceLock<ServiceBootstrap> = OnceLock::new();
static SERVICE_BOOTSTRAP_CLAIMED: AtomicBool = AtomicBool::new(false);
static SERVICE_BOOTSTRAP_MISSING_ATTEMPT: AtomicBool = AtomicBool::new(false);
static SERVICE_BIND_PROCESS_STATE: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct DescriptorError {
    code: &'static str,
    detail: String,
    errno: Option<libc::c_int>,
}

impl DescriptorError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            errno: None,
        }
    }

    fn io(code: &'static str, context: impl fmt::Display, error: io::Error) -> Self {
        Self {
            code,
            detail: format!("{context}: {error}"),
            errno: error.raw_os_error(),
        }
    }

    #[cfg(test)]
    fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dmux_descriptor_{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for DescriptorError {}

type DescriptorResult<T> = Result<T, DescriptorError>;

#[derive(Debug)]
struct RecoverySpoolError {
    code: &'static str,
    detail: String,
}

impl RecoverySpoolError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_descriptor(error: DescriptorError) -> Self {
        Self::new(error.code, error.detail)
    }
}

impl fmt::Display for RecoverySpoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dmux_recovery_spool_{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RecoverySpoolError {}

type RecoverySpoolResult<T> = Result<T, RecoverySpoolError>;

#[derive(Debug)]
struct RecoveryManifestError {
    code: &'static str,
    detail: String,
}

impl RecoveryManifestError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_descriptor(error: DescriptorError) -> Self {
        Self::new(error.code, error.detail)
    }
}

impl fmt::Display for RecoveryManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dmux_recovery_manifest_{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RecoveryManifestError {}

type RecoveryManifestResult<T> = Result<T, RecoveryManifestError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoverySpoolKind {
    Command,
    Response,
    Status,
    Control,
    InitialSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryManifestKind {
    Candidate,
    Plan,
    Published,
}

impl RecoveryManifestKind {
    fn parse(value: &str) -> RecoveryManifestResult<Self> {
        match value {
            "candidate" => Ok(Self::Candidate),
            "plan" => Ok(Self::Plan),
            "published" => Ok(Self::Published),
            _ => Err(RecoveryManifestError::new(
                "invalid_kind",
                "kind must be candidate, plan, or published",
            )),
        }
    }
}

impl RecoverySpoolKind {
    fn parse(value: &str) -> RecoverySpoolResult<Self> {
        match value {
            "command" => Ok(Self::Command),
            "response" => Ok(Self::Response),
            "status" => Ok(Self::Status),
            "control" => Ok(Self::Control),
            "initial_snapshot" => Ok(Self::InitialSnapshot),
            _ => Err(RecoverySpoolError::new(
                "invalid_kind",
                "kind must be command, response, status, control, or initial_snapshot",
            )),
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Command => "command.json",
            Self::Response => "response.json",
            Self::Status => "status.json",
            Self::Control => "control.json",
            Self::InitialSnapshot => "initial-snapshot.json",
        }
    }
}

#[derive(Debug)]
struct PrivateDir {
    file: File,
    display_path: PathBuf,
}

impl PrivateDir {
    fn open_platform_base(path: &Path) -> DescriptorResult<Self> {
        if !path.is_absolute() {
            return Err(DescriptorError::new(
                "runtime_unavailable",
                "platform runtime path is not absolute",
            ));
        }
        let path_c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            DescriptorError::new("runtime_unavailable", "platform runtime path contains NUL")
        })?;
        let fd = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(DescriptorError::io(
                "runtime_unavailable",
                path.display(),
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_directory(&file, path, None)?;
        Ok(Self {
            file,
            display_path: path.to_path_buf(),
        })
    }

    fn child(&self, name: &str) -> DescriptorResult<Self> {
        validate_component(name)?;
        let name_c = CString::new(name).expect("validated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(DescriptorError::io(
                "unsafe_directory",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let display_path = self.display_path.join(name);
        validate_directory(&file, &display_path, Some(0o700))?;
        Ok(Self { file, display_path })
    }

    fn ensure_child(&self, name: &str) -> DescriptorResult<Self> {
        validate_component(name)?;
        let name_c = CString::new(name).expect("validated component");
        let rc = unsafe { libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), 0o700) };
        let created = if rc == 0 {
            true
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(DescriptorError::io(
                    "create_directory",
                    self.display_path.join(name).display(),
                    error,
                ));
            }
            false
        };
        let child = self.child(name)?;
        if created {
            if unsafe { libc::fchmod(child.file.as_raw_fd(), 0o700) } != 0 {
                return Err(DescriptorError::io(
                    "create_directory",
                    child.display_path.display(),
                    io::Error::last_os_error(),
                ));
            }
            validate_directory(&child.file, &child.display_path, Some(0o700))?;
            sync_directory(&self.file)?;
        }
        Ok(child)
    }

    fn open_private_optional(&self, name: &str) -> DescriptorResult<Option<File>> {
        self.open_private_optional_with_access(name, libc::O_RDONLY)
    }

    fn open_private_rw_optional(&self, name: &str) -> DescriptorResult<Option<File>> {
        self.open_private_optional_with_access(name, libc::O_RDWR)
    }

    fn open_or_create_private_rw(&self, name: &str) -> DescriptorResult<File> {
        validate_component(name)?;
        let name_c = CString::new(name).expect("validated component");
        let exclusive_fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        let (fd, created) = if exclusive_fd >= 0 {
            (exclusive_fd, true)
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(DescriptorError::io(
                    "unsafe_file",
                    self.display_path.join(name).display(),
                    error,
                ));
            }
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            (fd, false)
        };
        if fd < 0 {
            return Err(DescriptorError::io(
                "unsafe_file",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if created && unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(DescriptorError::io(
                "unsafe_file",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        validate_private_file(&file, &self.display_path.join(name))?;
        if created {
            sync_directory(&self.file)?;
        }
        Ok(file)
    }

    fn open_private_optional_with_access(
        &self,
        name: &str,
        access: libc::c_int,
    ) -> DescriptorResult<Option<File>> {
        validate_component(name)?;
        let name_c = CString::new(name).expect("validated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                access | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(DescriptorError::io(
                "unsafe_file",
                self.display_path.join(name).display(),
                error,
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_private_file(&file, &self.display_path.join(name))?;
        Ok(Some(file))
    }

    fn create_private_temp(
        &self,
        bytes: &[u8],
        maximum: usize,
    ) -> DescriptorResult<(String, File)> {
        if bytes.len() > maximum {
            return Err(DescriptorError::new(
                "invalid_descriptor",
                format!("document exceeds {maximum} bytes"),
            ));
        }
        let name = format!(".wez-dmux.json.tmp-{}", Uuid::new_v4());
        let name_c = CString::new(name.as_str()).expect("generated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(DescriptorError::io(
                "publish_failed",
                self.display_path.join(&name).display(),
                io::Error::last_os_error(),
            ));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> io::Result<()> {
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(io::Error::last_os_error());
            }
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if let Err(error) = result {
            let _ = self.unlink(&name);
            return Err(DescriptorError::io(
                "publish_failed",
                self.display_path.join(&name).display(),
                error,
            ));
        }
        validate_private_file(&file, &self.display_path.join(&name))?;
        Ok((name, file))
    }

    fn publish_replace(&self, bytes: &[u8]) -> DescriptorResult<()> {
        self.publish_named_replace(DESCRIPTOR_FILE, bytes, MAX_DESCRIPTOR_BYTES)
    }

    fn publish_named_replace(
        &self,
        name: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> DescriptorResult<()> {
        validate_component(name)?;
        // A valid previous file is replaceable.  Keep its descriptor and move
        // the selected name into a private quarantine slot before installing
        // the new bytes.  Both moves are no-replace operations: a same-UID
        // name swap is detected without overwriting or deleting the object
        // that raced us.
        let existing = self.open_private_rw_optional(name)?;
        let existing_identity = existing
            .as_ref()
            .map(|file| {
                file.metadata().map_err(|error| {
                    DescriptorError::io(
                        "publish_failed",
                        self.display_path.join(name).display(),
                        error,
                    )
                })
            })
            .transpose()?;
        let (temporary, file) = self.create_private_temp(bytes, maximum)?;
        let temporary_c = CString::new(temporary.as_str()).expect("generated component");
        let destination_c = CString::new(name).expect("validated component");
        let mut quarantine = None;
        if let Some(expected) = existing_identity {
            let quarantine_name = format!(".replace-{}", Uuid::new_v4());
            let quarantine_c = CString::new(quarantine_name.as_str()).expect("generated component");
            if rename_noreplace(
                self.file.as_raw_fd(),
                &destination_c,
                self.file.as_raw_fd(),
                &quarantine_c,
            ) != 0
            {
                let error = io::Error::last_os_error();
                let _ = self.unlink(&temporary);
                return Err(DescriptorError::io(
                    "publish_failed",
                    self.display_path.join(name).display(),
                    error,
                ));
            }
            let moved = self
                .open_private_optional(&quarantine_name)?
                .ok_or_else(|| {
                    DescriptorError::new("publish_failed", "quarantined file disappeared")
                })?;
            let moved_identity = moved.metadata().map_err(|error| {
                DescriptorError::io(
                    "publish_failed",
                    self.display_path.join(&quarantine_name).display(),
                    error,
                )
            })?;
            if expected.dev() != moved_identity.dev() || expected.ino() != moved_identity.ino() {
                drop(moved);
                let _ = rename_noreplace(
                    self.file.as_raw_fd(),
                    &quarantine_c,
                    self.file.as_raw_fd(),
                    &destination_c,
                );
                let _ = self.unlink(&temporary);
                return Err(DescriptorError::new(
                    "publish_failed",
                    format!("{name:?} changed before atomic quarantine"),
                ));
            }
            drop(moved);
            quarantine = Some((quarantine_name, quarantine_c));
        }
        if rename_noreplace(
            self.file.as_raw_fd(),
            &temporary_c,
            self.file.as_raw_fd(),
            &destination_c,
        ) != 0
        {
            let error = io::Error::last_os_error();
            let _ = self.unlink(&temporary);
            if let Some((_, quarantine_c)) = &quarantine {
                let _ = rename_noreplace(
                    self.file.as_raw_fd(),
                    quarantine_c,
                    self.file.as_raw_fd(),
                    &destination_c,
                );
            }
            return Err(DescriptorError::io(
                "publish_failed",
                self.display_path.join(name).display(),
                error,
            ));
        }
        drop(file);
        let mut published = self
            .open_private_optional(name)?
            .ok_or_else(|| DescriptorError::new("publish_failed", "descriptor disappeared"))?;
        let actual = read_held_bounded(&mut published, &self.display_path.join(name), maximum)?;
        if actual != bytes {
            return Err(DescriptorError::new(
                "publish_failed",
                "published descriptor bytes changed",
            ));
        }
        if let Some((_, _)) = quarantine {
            let existing = existing.expect("quarantine exists only for a held previous file");
            if unsafe { libc::ftruncate(existing.as_raw_fd(), 0) } != 0 {
                return Err(DescriptorError::io(
                    "publish_failed",
                    "truncate replaced private file",
                    io::Error::last_os_error(),
                ));
            }
            existing.sync_all().map_err(|error| {
                DescriptorError::io("publish_failed", "sync replaced private file", error)
            })?;
        }
        sync_directory(&self.file)
    }

    fn read_private_named(&self, name: &str, maximum: usize) -> DescriptorResult<Option<Vec<u8>>> {
        let Some(mut file) = self.open_private_optional(name)? else {
            return Ok(None);
        };
        read_held_bounded(&mut file, &self.display_path.join(name), maximum).map(Some)
    }

    fn remove_private_verified(&self, name: &str) -> DescriptorResult<bool> {
        self.remove_private_verified_with_hook(name, |_| {})
    }

    fn remove_private_verified_with_hook<F>(
        &self,
        name: &str,
        after_verify: F,
    ) -> DescriptorResult<bool>
    where
        F: FnOnce(&Path),
    {
        let Some(held) = self.open_private_rw_optional(name)? else {
            return Ok(false);
        };
        let before = held.metadata().map_err(|error| {
            DescriptorError::io(
                "remove_failed",
                self.display_path.join(name).display(),
                error,
            )
        })?;
        // Move the selected name into an unguessable private quarantine slot
        // first.  We only unlink after opening that slot and proving that the
        // atomic rename moved the inode held above.  A name swap therefore
        // cannot make us delete the replacement.
        let quarantine = format!(".remove-{}", Uuid::new_v4());
        let name_c = CString::new(name).expect("validated component");
        let quarantine_c = CString::new(quarantine.as_str()).expect("generated component");
        if rename_noreplace(
            self.file.as_raw_fd(),
            &name_c,
            self.file.as_raw_fd(),
            &quarantine_c,
        ) != 0
        {
            return Err(DescriptorError::io(
                "remove_failed",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        let moved = self
            .open_private_optional(&quarantine)?
            .ok_or_else(|| DescriptorError::new("remove_failed", "quarantined file disappeared"))?;
        let moved_metadata = moved.metadata().map_err(|error| {
            DescriptorError::io(
                "remove_failed",
                self.display_path.join(&quarantine).display(),
                error,
            )
        })?;
        if before.dev() != moved_metadata.dev() || before.ino() != moved_metadata.ino() {
            drop(moved);
            // Preserve the unexpected object.  Restore it only if the source
            // name is still absent; never overwrite a concurrent replacement.
            let _ = rename_noreplace(
                self.file.as_raw_fd(),
                &quarantine_c,
                self.file.as_raw_fd(),
                &name_c,
            );
            return Err(DescriptorError::new(
                "remove_failed",
                format!("{name:?} changed before atomic quarantine"),
            ));
        }
        drop(moved);
        after_verify(&self.display_path.join(&quarantine));
        // Never unlink by name after verification: another same-UID actor can
        // swap even an unguessable quarantine entry between fstat and unlink.
        // Truncating through the held descriptor is inode-stable.  The empty
        // quarantine entry is intentionally retained; the public protocol name
        // has been atomically consumed without risking deletion of a racer.
        if unsafe { libc::ftruncate(held.as_raw_fd(), 0) } != 0 {
            return Err(DescriptorError::io(
                "remove_failed",
                "truncate quarantined private file",
                io::Error::last_os_error(),
            ));
        }
        held.sync_all().map_err(|error| {
            DescriptorError::io("remove_failed", "sync quarantined private file", error)
        })?;
        sync_directory(&self.file)?;
        Ok(true)
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        let name_c = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in component"))?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name_c.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Process-owned capability established while the mux configuration is being
/// evaluated and retained through listener creation and descriptor updates.
/// The lease and directory descriptors are never exposed to Lua.
struct ServiceBootstrap {
    base_path: PathBuf,
    base: PrivateDir,
    runtime: PrivateDir,
    lease: File,
    socket_path: PathBuf,
    listener: Mutex<Option<wezterm_uds::UnixListener>>,
    bound_socket: Option<SocketWitness>,
}

impl ServiceBootstrap {
    fn initialize() -> DescriptorResult<Self> {
        let base_path = platform_runtime_base()?;
        Self::initialize_at_base(&base_path)
    }

    fn initialize_at_base(base_path: &Path) -> DescriptorResult<Self> {
        let base = PrivateDir::open_platform_base(base_path)?;
        let runtime = base.ensure_child(RUNTIME_DIR)?;
        let lease = acquire_service_lease(&runtime)?;
        let state = Self {
            base_path: base_path.to_path_buf(),
            socket_path: runtime.display_path.join(SOCKET_FILE),
            base,
            runtime,
            lease,
            listener: Mutex::new(None),
            bound_socket: None,
        };
        state.revalidate()?;
        // Invalidate stale ready bytes before any later schema/listener error
        // can abort startup.  Attach readers therefore fail closed throughout
        // the starting interval.
        state.runtime.remove_private_verified(DESCRIPTOR_FILE)?;
        state.prepare_socket_absent()?;
        Ok(state)
    }

    fn revalidate(&self) -> DescriptorResult<()> {
        revalidate_runtime_path(&self.base_path, &self.base, &self.runtime)?;
        validate_private_file(
            &self.lease,
            &self.runtime.display_path.join(SERVICE_LEASE_FILE),
        )?;
        let current = self
            .runtime
            .open_private_optional(SERVICE_LEASE_FILE)?
            .ok_or_else(|| DescriptorError::new("service_lease_lost", "lease path is absent"))?;
        let held = self.lease.metadata().map_err(|error| {
            DescriptorError::io("service_lease_lost", "held service lease", error)
        })?;
        let current = current.metadata().map_err(|error| {
            DescriptorError::io("service_lease_lost", "current service lease", error)
        })?;
        if held.dev() != current.dev() || held.ino() != current.ino() {
            return Err(DescriptorError::new(
                "service_lease_lost",
                "service lease path no longer names the held locked inode",
            ));
        }
        Ok(())
    }

    fn prepare_socket_absent(&self) -> DescriptorResult<()> {
        self.revalidate()?;
        let Some(identity) = socket_stat(&self.runtime)? else {
            return Ok(());
        };
        match connect_unix_bounded(&self.socket_path) {
            Ok(connection) => {
                let peer = peer_pid(&connection)?;
                return Err(DescriptorError::new(
                    "duplicate_service",
                    format!("fixed mux socket is already served by pid {peer}"),
                ));
            }
            Err(error) if error.errno == Some(libc::ECONNREFUSED) => {}
            Err(error) => {
                return Err(DescriptorError::new(
                    "socket_live_or_unknown",
                    format!("existing fixed socket was not proven stale by ECONNREFUSED: {error}"),
                ))
            }
        }
        quarantine_socket(&self.runtime, identity)?;
        self.revalidate()?;
        if socket_stat(&self.runtime)?.is_some() {
            return Err(DescriptorError::new(
                "socket_changed",
                "fixed socket name was recreated during stale-socket quarantine",
            ));
        }
        Ok(())
    }
}

fn acquire_service_lease(runtime: &PrivateDir) -> DescriptorResult<File> {
    let mut lease = runtime.open_or_create_private_rw(SERVICE_LEASE_FILE)?;
    if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(DescriptorError::io(
            "duplicate_service",
            runtime.display_path.join(SERVICE_LEASE_FILE).display(),
            io::Error::last_os_error(),
        ));
    }
    let current = runtime
        .open_private_optional(SERVICE_LEASE_FILE)?
        .ok_or_else(|| DescriptorError::new("service_lease_lost", "lease path is absent"))?;
    let held_metadata = lease
        .metadata()
        .map_err(|error| DescriptorError::io("service_lease_lost", "held service lease", error))?;
    let current_metadata = current.metadata().map_err(|error| {
        DescriptorError::io("service_lease_lost", "current service lease", error)
    })?;
    if held_metadata.dev() != current_metadata.dev()
        || held_metadata.ino() != current_metadata.ino()
    {
        return Err(DescriptorError::new(
            "service_lease_lost",
            "service lease changed while it was acquired",
        ));
    }
    let body = format!(
        "{{\"lease_version\":1,\"pid\":{},\"start_token\":{}}}\n",
        std::process::id(),
        serde_json::to_string(&process_start_token(std::process::id())?)
            .expect("start token serialization"),
    );
    lease
        .set_len(0)
        .and_then(|_| lease.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|_| lease.write_all(body.as_bytes()))
        .and_then(|_| lease.sync_all())
        .map_err(|error| DescriptorError::io("service_lease_lost", "write lease", error))?;
    sync_directory(&runtime.file)?;
    Ok(lease)
}

pub struct ManagedServiceBootstrap {
    consumed: bool,
}

pub struct ManagedServiceGuard {
    _private: (),
}

pub fn service_bootstrap_missing_prebind_attempted() -> bool {
    SERVICE_BOOTSTRAP_MISSING_ATTEMPT.load(Ordering::Acquire)
}

/// Called from the hidden managed-service CLI path before config loading or
/// executor/watcher startup.  This is the only function that may bind the
/// fixed service socket.
pub fn prebind_dmux_managed_service() -> anyhow::Result<ManagedServiceBootstrap> {
    let threads = current_process_thread_count().map_err(anyhow::Error::new)?;
    anyhow::ensure!(
        threads == 1,
        "dmux managed service prebind requires one OS thread, found {threads}"
    );
    anyhow::ensure!(
        SERVICE_BOOTSTRAP.get().is_none(),
        "dmux managed service was already prebound"
    );
    let mut state = ServiceBootstrap::initialize().map_err(anyhow::Error::new)?;
    let listener = bind_service_socket_early(&state).map_err(anyhow::Error::new)?;
    let witness = socket_witness(&state.runtime, true)
        .map_err(anyhow::Error::new)?
        .ok_or_else(|| anyhow::anyhow!("prebound dmux socket disappeared"))?;
    state.bound_socket = Some(witness);
    *state
        .listener
        .lock()
        .map_err(|_| anyhow::anyhow!("dmux managed listener state mutex was poisoned"))? =
        Some(listener);
    SERVICE_BOOTSTRAP
        .set(state)
        .map_err(|_| anyhow::anyhow!("dmux managed service bootstrap raced another prebind"))?;
    Ok(ManagedServiceBootstrap { consumed: false })
}

impl ManagedServiceBootstrap {
    pub fn validate_and_take(
        mut self,
        config: &config::ConfigHandle,
    ) -> anyhow::Result<(wezterm_uds::UnixListener, ManagedServiceGuard)> {
        anyhow::ensure!(
            SERVICE_BOOTSTRAP_CLAIMED.load(Ordering::Acquire),
            "managed mux config did not call wezterm.mux.dmux_service_bootstrap()"
        );
        anyhow::ensure!(
            config.dmux_recovery_primitives,
            "managed mux config must enable dmux_recovery_primitives"
        );
        anyhow::ensure!(
            config.unix_domains.len() == 1,
            "managed mux config must declare exactly one Unix domain"
        );
        anyhow::ensure!(
            config.tls_servers.is_empty(),
            "managed mux config must not expose TLS listeners"
        );
        let state = SERVICE_BOOTSTRAP
            .get()
            .ok_or_else(|| anyhow::anyhow!("managed service bootstrap state is absent"))?;
        state.revalidate().map_err(anyhow::Error::new)?;
        let domain = &config.unix_domains[0];
        anyhow::ensure!(
            domain.name == "dmux"
                && domain.socket_path.as_deref() == Some(state.socket_path.as_path())
                && domain.no_serve_automatically
                && !domain.connect_automatically
                && !domain.skip_permissions_check
                && domain.serve_command.is_none()
                && domain.proxy_command.is_none(),
            "managed mux domain does not match the exact fixed prebound service contract"
        );
        let expected = state
            .bound_socket
            .ok_or_else(|| anyhow::anyhow!("managed service has no bound socket witness"))?;
        let actual = socket_witness(&state.runtime, true)
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| anyhow::anyhow!("prebound managed socket is absent"))?;
        anyhow::ensure!(
            actual == expected && actual.peer_pid == std::process::id(),
            "prebound managed socket identity changed before listener handoff"
        );
        let listener = state
            .listener
            .lock()
            .map_err(|_| anyhow::anyhow!("managed listener state mutex was poisoned"))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("managed listener was already consumed"))?;
        self.consumed = true;
        Ok((listener, ManagedServiceGuard { _private: () }))
    }
}

impl Drop for ManagedServiceBootstrap {
    fn drop(&mut self) {
        if !self.consumed {
            if let Some(state) = SERVICE_BOOTSTRAP.get() {
                if let Ok(mut listener) = state.listener.lock() {
                    listener.take();
                }
            }
        }
    }
}

fn bind_service_socket_early(
    state: &ServiceBootstrap,
) -> DescriptorResult<wezterm_uds::UnixListener> {
    state.revalidate()?;
    state.prepare_socket_absent()?;
    let _process_state = SERVICE_BIND_PROCESS_STATE.lock().map_err(|_| {
        DescriptorError::new(
            "bind_failed",
            "managed socket bind state mutex was poisoned",
        )
    })?;
    state.revalidate()?;

    let cwd = CwdRestore::enter(&state.runtime.file)?;
    let private_umask = UmaskRestore::private();
    let listener = wezterm_uds::UnixListener::bind(SOCKET_FILE).map_err(|error| {
        DescriptorError::io(
            "bind_failed",
            state.runtime.display_path.join(SOCKET_FILE).display(),
            error,
        )
    })?;
    drop(private_umask);
    // Do not chmod the path after bind: a pathname chmod could follow a
    // same-UID replacement symlink before the inode identity checks below.
    // The single-threaded private umask creates the socket privately, and
    // `socket_witness` independently verifies that fact.
    cwd.restore()?;

    state.revalidate()?;
    let before = socket_witness(&state.runtime, true)?
        .ok_or_else(|| DescriptorError::new("bind_failed", "bound fixed socket is absent"))?;
    if before.peer_pid != std::process::id() {
        return Err(DescriptorError::new(
            "socket_identity",
            "bound fixed socket does not route to this service process",
        ));
    }
    let after = socket_witness(&state.runtime, true)?
        .ok_or_else(|| DescriptorError::new("socket_changed", "bound fixed socket disappeared"))?;
    if before != after {
        return Err(DescriptorError::new(
            "socket_changed",
            "bound fixed socket changed before listener handoff",
        ));
    }
    state.revalidate()?;
    sync_directory(&state.runtime.file)?;
    Ok(listener)
}

struct CwdRestore {
    previous: File,
    restored: bool,
}

struct UmaskRestore {
    previous: libc::mode_t,
}

impl UmaskRestore {
    fn private() -> Self {
        Self {
            previous: unsafe { libc::umask(0o077) },
        }
    }
}

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

impl CwdRestore {
    fn enter(directory: &File) -> DescriptorResult<Self> {
        let dot = CString::new(".").expect("static component");
        let fd = unsafe {
            libc::open(
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(DescriptorError::io(
                "bind_failed",
                "open current directory",
                io::Error::last_os_error(),
            ));
        }
        let previous = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::fchdir(directory.as_raw_fd()) } != 0 {
            return Err(DescriptorError::io(
                "bind_failed",
                "enter held dmux runtime directory",
                io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            previous,
            restored: false,
        })
    }

    fn restore(mut self) -> DescriptorResult<()> {
        self.restore_inner()?;
        self.restored = true;
        Ok(())
    }

    fn restore_inner(&self) -> DescriptorResult<()> {
        if unsafe { libc::fchdir(self.previous.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(DescriptorError::io(
                "bind_failed",
                "restore current directory",
                io::Error::last_os_error(),
            ))
        }
    }
}

impl Drop for CwdRestore {
    fn drop(&mut self) {
        if !self.restored && self.restore_inner().is_err() {
            // Continuing in an attacker-selected cwd would turn later
            // relative operations into path authority.  This branch is only
            // reachable during single-threaded process bootstrap.
            unsafe { libc::_exit(125) }
        }
    }
}

#[cfg(target_os = "linux")]
fn current_process_thread_count() -> DescriptorResult<usize> {
    std::fs::read_dir("/proc/self/task")
        .map_err(|error| DescriptorError::io("thread_count", "/proc/self/task", error))
        .and_then(|entries| {
            entries
                .collect::<Result<Vec<_>, _>>()
                .map(|entries| entries.len())
                .map_err(|error| DescriptorError::io("thread_count", "/proc/self/task", error))
        })
}

#[cfg(target_os = "macos")]
fn current_process_thread_count() -> DescriptorResult<usize> {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int,
        )
    };
    if size != std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int {
        return Err(DescriptorError::io(
            "thread_count",
            "proc_pidinfo(PROC_PIDTASKINFO)",
            io::Error::last_os_error(),
        ));
    }
    Ok(info.pti_threadnum as usize)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceDescriptor {
    descriptor_version: u32,
    state: String,
    epoch: String,
    pid: u32,
    socket: String,
    socket_dev: Option<u64>,
    socket_ino: Option<u64>,
    start_token: String,
    backend_instance_uid: Option<String>,
    boot_nonce: String,
    boot_id: String,
    written_by: String,
    written_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sentinel_window_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sentinel_tab_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sentinel_pane_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sentinel_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_manifest_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug)]
struct PublishRequest {
    state: String,
    epoch: String,
    backend_instance_uid: Option<String>,
    boot_nonce: String,
    sentinel_window_id: Option<u64>,
    sentinel_tab_id: Option<u64>,
    sentinel_pane_id: Option<u64>,
    sentinel_fallback: Option<bool>,
    recovery_generation: Option<String>,
    recovery_manifest_id: Option<String>,
    error: Option<String>,
}

impl PublishRequest {
    fn from_lua(request: Table) -> mlua::Result<Self> {
        const ALLOWED: &[&str] = &[
            "state",
            "epoch",
            "backend_instance_uid",
            "boot_nonce",
            "sentinel_window_id",
            "sentinel_tab_id",
            "sentinel_pane_id",
            "sentinel_fallback",
            "recovery_generation",
            "recovery_manifest_id",
            "error",
        ];
        for pair in request.clone().pairs::<LuaValue, LuaValue>() {
            let (key, _) = pair?;
            let key = match key {
                LuaValue::String(value) => value.to_str()?.to_string(),
                other => {
                    return Err(mlua::Error::external(format!(
                        "dmux_descriptor_invalid_request: input key is {} rather than a string",
                        other.type_name()
                    )));
                }
            };
            if !ALLOWED.contains(&key.as_str()) {
                return Err(mlua::Error::external(format!(
                    "dmux_descriptor_invalid_request: unknown publisher field {key:?}"
                )));
            }
        }
        Ok(Self {
            state: request.raw_get("state")?,
            epoch: request.raw_get("epoch")?,
            backend_instance_uid: request.raw_get("backend_instance_uid")?,
            boot_nonce: request.raw_get("boot_nonce")?,
            sentinel_window_id: request.raw_get("sentinel_window_id")?,
            sentinel_tab_id: request.raw_get("sentinel_tab_id")?,
            sentinel_pane_id: request.raw_get("sentinel_pane_id")?,
            sentinel_fallback: request.raw_get("sentinel_fallback")?,
            recovery_generation: request.raw_get("recovery_generation")?,
            recovery_manifest_id: request.raw_get("recovery_manifest_id")?,
            error: request.raw_get("error")?,
        })
    }

    fn validate(&self) -> DescriptorResult<()> {
        if !matches!(
            self.state.as_str(),
            "starting" | "recovering" | "ready" | "failed"
        ) {
            return Err(DescriptorError::new(
                "invalid_request",
                "state must be starting, recovering, ready, or failed",
            ));
        }
        for (name, value) in [("epoch", &self.epoch), ("boot_nonce", &self.boot_nonce)] {
            validate_uuid(name, value)?;
        }
        if let Some(backend_instance_uid) = &self.backend_instance_uid {
            validate_uuid("backend_instance_uid", backend_instance_uid)?;
        }
        if matches!(self.state.as_str(), "recovering" | "ready")
            && self.backend_instance_uid.is_none()
        {
            return Err(DescriptorError::new(
                "invalid_request",
                "recovering and ready publication require backend_instance_uid",
            ));
        }
        let sentinel_count = [
            self.sentinel_window_id.is_some(),
            self.sentinel_tab_id.is_some(),
            self.sentinel_pane_id.is_some(),
            self.sentinel_fallback.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if sentinel_count != 0 && sentinel_count != 4 {
            return Err(DescriptorError::new(
                "invalid_request",
                "sentinel fields must be supplied together",
            ));
        }
        for (name, value) in [
            ("sentinel_window_id", self.sentinel_window_id),
            ("sentinel_tab_id", self.sentinel_tab_id),
            ("sentinel_pane_id", self.sentinel_pane_id),
        ] {
            if value.is_some_and(|value| value > MAX_JSON_INTEGER) {
                return Err(DescriptorError::new(
                    "invalid_request",
                    format!("{name} exceeds the exact JSON/Lua integer range"),
                ));
            }
        }
        if self.state == "ready" && (sentinel_count != 4 || self.sentinel_fallback != Some(false)) {
            return Err(DescriptorError::new(
                "invalid_request",
                "ready publication requires a complete non-fallback sentinel",
            ));
        }
        if let Some(generation) = &self.recovery_generation {
            validate_uuid("recovery_generation", generation)?;
        }
        if let Some(manifest) = &self.recovery_manifest_id {
            validate_bounded_text("recovery_manifest_id", manifest, 256)?;
        }
        if let Some(error) = &self.error {
            validate_bounded_text("error", error, 1024)?;
        }
        if self.state == "failed" && self.error.is_none() {
            return Err(DescriptorError::new(
                "invalid_request",
                "failed publication requires error",
            ));
        }
        if self.state != "failed" && self.error.is_some() {
            return Err(DescriptorError::new(
                "invalid_request",
                "error is accepted only for failed publication",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketWitness {
    dev: u64,
    ino: u64,
    peer_pid: u32,
}

#[derive(Debug)]
struct PublishedDescriptor {
    descriptor: ServiceDescriptor,
    raw: Vec<u8>,
    peer_pid: Option<u32>,
}

pub fn register(lua: &Lua, mux_mod: &Table) -> anyhow::Result<()> {
    mux_mod.set(
        "dmux_service_bootstrap",
        lua.create_function(|lua, _: ()| {
            let state = SERVICE_BOOTSTRAP.get().ok_or_else(|| {
                SERVICE_BOOTSTRAP_MISSING_ATTEMPT.store(true, Ordering::Release);
                mlua::Error::external(
                    "dmux_descriptor_early_prebind_required: start wezterm-mux-server with --dmux-managed-service",
                )
            })?;
            state.revalidate().map_err(mlua::Error::external)?;
            SERVICE_BOOTSTRAP_CLAIMED.store(true, Ordering::Release);
            let result = lua.create_table()?;
            result.set(
                "runtime_dir",
                path_to_descriptor_string(&state.runtime.display_path)
                    .map_err(mlua::Error::external)?,
            )?;
            result.set(
                "socket_path",
                path_to_descriptor_string(&state.socket_path).map_err(mlua::Error::external)?,
            )?;
            result.set("api_version", DESCRIPTOR_VERSION)?;
            Ok(result)
        })?,
    )?;
    mux_mod.set(
        "dmux_invalidate_service_descriptor",
        lua.create_function(|_, _: ()| {
            let state = SERVICE_BOOTSTRAP.get().ok_or_else(|| {
                mlua::Error::external(
                    "dmux_descriptor_bootstrap_required: call dmux_service_bootstrap first",
                )
            })?;
            state.revalidate().map_err(mlua::Error::external)?;
            state
                .runtime
                .remove_private_verified(DESCRIPTOR_FILE)
                .map_err(mlua::Error::external)
        })?,
    )?;
    mux_mod.set(
        "dmux_publish_service_descriptor",
        lua.create_function(|lua, request: Table| {
            let request = PublishRequest::from_lua(request)?;
            let published = publish_service_descriptor(request).map_err(mlua::Error::external)?;
            let value = lua.to_value(&published.descriptor)?;
            let table = match value {
                LuaValue::Table(table) => table,
                _ => unreachable!("serialized descriptor is a table"),
            };
            table.set("peer_pid", published.peer_pid)?;
            let raw = lua.create_string(&published.raw)?;
            Ok((table, raw))
        })?,
    )?;
    mux_mod.set(
        "dmux_recovery_spool_open",
        lua.create_function(|_, epoch: String| {
            require_recovery_gate()?;
            RecoverySpoolHandle::open(&epoch).map_err(mlua::Error::external)
        })?,
    )?;
    mux_mod.set(
        "dmux_recovery_manifest_open",
        lua.create_function(|_, _: ()| {
            require_recovery_gate()?;
            RecoveryManifestHandle::open().map_err(mlua::Error::external)
        })?,
    )?;
    Ok(())
}

fn require_recovery_gate() -> mlua::Result<()> {
    if config::configuration().dmux_recovery_primitives {
        Ok(())
    } else {
        Err(mlua::Error::external(
            "dmux_recovery_spool_disabled: dmux_recovery_primitives is not enabled",
        ))
    }
}

fn recovery_epoch_dir(epoch: &str) -> RecoverySpoolResult<PrivateDir> {
    validate_uuid("epoch", epoch).map_err(RecoverySpoolError::from_descriptor)?;
    let base_path = platform_runtime_base().map_err(RecoverySpoolError::from_descriptor)?;
    recovery_epoch_dir_at_base(&base_path, epoch)
}

fn recovery_epoch_dir_at_base(base_path: &Path, epoch: &str) -> RecoverySpoolResult<PrivateDir> {
    validate_uuid("epoch", epoch).map_err(RecoverySpoolError::from_descriptor)?;
    let base =
        PrivateDir::open_platform_base(base_path).map_err(RecoverySpoolError::from_descriptor)?;
    let runtime = base
        .ensure_child(RUNTIME_DIR)
        .map_err(RecoverySpoolError::from_descriptor)?;
    let recovery = runtime
        .ensure_child("recovery")
        .map_err(RecoverySpoolError::from_descriptor)?;
    recovery
        .ensure_child(epoch)
        .map_err(RecoverySpoolError::from_descriptor)
}

#[derive(Debug)]
struct RecoverySpoolHandle {
    epoch: String,
    directory: PrivateDir,
}

impl RecoverySpoolHandle {
    fn open(epoch: &str) -> RecoverySpoolResult<Self> {
        Ok(Self {
            epoch: epoch.to_string(),
            directory: recovery_epoch_dir(epoch)?,
        })
    }
}

impl UserData for RecoverySpoolHandle {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("epoch", |_, this, _: ()| Ok(this.epoch.clone()));
        methods.add_method("read", |lua, this, (kind, maximum): (String, usize)| {
            require_recovery_gate()?;
            recovery_spool_read_from_dir(&this.directory, &kind, maximum)
                .map_err(mlua::Error::external)?
                .map(|bytes| lua.create_string(&bytes))
                .transpose()
        });
        methods.add_method("write", |_, this, (kind, raw): (String, LuaString)| {
            require_recovery_gate()?;
            recovery_spool_write_to_dir(&this.directory, &kind, raw.as_bytes().as_ref())
                .map_err(mlua::Error::external)?;
            Ok(true)
        });
        methods.add_method("remove", |_, this, kind: String| {
            require_recovery_gate()?;
            recovery_spool_remove_from_dir(&this.directory, &kind).map_err(mlua::Error::external)
        });
    }
}

fn recovery_spool_read_from_dir(
    epoch_dir: &PrivateDir,
    kind: &str,
    maximum: usize,
) -> RecoverySpoolResult<Option<Vec<u8>>> {
    if maximum == 0 || maximum > MAX_RECOVERY_MESSAGE_BYTES {
        return Err(RecoverySpoolError::new(
            "invalid_limit",
            format!("max_bytes must be between 1 and {MAX_RECOVERY_MESSAGE_BYTES}"),
        ));
    }
    let kind = RecoverySpoolKind::parse(kind)?;
    epoch_dir
        .read_private_named(kind.file_name(), maximum)
        .map_err(RecoverySpoolError::from_descriptor)
}

fn recovery_spool_write_to_dir(
    epoch_dir: &PrivateDir,
    kind: &str,
    raw: &[u8],
) -> RecoverySpoolResult<()> {
    if raw.len() > MAX_RECOVERY_MESSAGE_BYTES {
        return Err(RecoverySpoolError::new(
            "message_too_large",
            format!(
                "recovery document is {} bytes; maximum is {MAX_RECOVERY_MESSAGE_BYTES}",
                raw.len()
            ),
        ));
    }
    let kind = RecoverySpoolKind::parse(kind)?;
    epoch_dir
        .publish_named_replace(kind.file_name(), raw, MAX_RECOVERY_MESSAGE_BYTES)
        .map_err(RecoverySpoolError::from_descriptor)
}

fn recovery_spool_remove_from_dir(epoch_dir: &PrivateDir, kind: &str) -> RecoverySpoolResult<bool> {
    let kind = RecoverySpoolKind::parse(kind)?;
    epoch_dir
        .remove_private_verified(kind.file_name())
        .map_err(RecoverySpoolError::from_descriptor)
}

#[derive(Debug)]
struct RecoveryManifestHandle {
    root: PrivateDir,
}

impl RecoveryManifestHandle {
    fn open() -> RecoveryManifestResult<Self> {
        Ok(Self {
            root: recovery_manifest_root()?,
        })
    }
}

impl UserData for RecoveryManifestHandle {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method(
            "write_candidate",
            |_, this, (candidate_name, raw): (String, LuaString)| {
                require_recovery_gate()?;
                recovery_manifest_write_candidate_at_root(
                    &this.root,
                    &candidate_name,
                    raw.as_bytes().as_ref(),
                )
                .map_err(mlua::Error::external)?;
                Ok(candidate_name)
            },
        );
        methods.add_method(
            "read",
            |lua, this, (candidate_name, kind, maximum): (String, String, usize)| {
                require_recovery_gate()?;
                recovery_manifest_read_at_root(&this.root, &candidate_name, &kind, maximum)
                    .map_err(mlua::Error::external)?
                    .map(|bytes| lua.create_string(&bytes))
                    .transpose()
            },
        );
        methods.add_method(
            "remove",
            |_, this, (candidate_name, kind): (String, String)| {
                require_recovery_gate()?;
                recovery_manifest_remove_at_root(&this.root, &candidate_name, &kind)
                    .map_err(mlua::Error::external)
            },
        );
    }
}

fn recovery_manifest_write_candidate_at_root(
    root: &PrivateDir,
    candidate_name: &str,
    raw: &[u8],
) -> RecoveryManifestResult<()> {
    let names = recovery_manifest_names(candidate_name)?;
    if raw.len() > MAX_RECOVERY_MANIFEST_BYTES {
        return Err(RecoveryManifestError::new(
            "message_too_large",
            format!(
                "candidate is {} bytes; maximum is {MAX_RECOVERY_MANIFEST_BYTES}",
                raw.len()
            ),
        ));
    }
    root.publish_named_replace(&names.0, raw, MAX_RECOVERY_MANIFEST_BYTES)
        .map_err(RecoveryManifestError::from_descriptor)?;
    Ok(())
}

fn recovery_manifest_read_at_root(
    root: &PrivateDir,
    candidate_name: &str,
    kind: &str,
    maximum: usize,
) -> RecoveryManifestResult<Option<Vec<u8>>> {
    if maximum == 0 || maximum > MAX_RECOVERY_MANIFEST_BYTES {
        return Err(RecoveryManifestError::new(
            "invalid_limit",
            format!("max_bytes must be between 1 and {MAX_RECOVERY_MANIFEST_BYTES}"),
        ));
    }
    let names = recovery_manifest_names(candidate_name)?;
    let name = match RecoveryManifestKind::parse(kind)? {
        RecoveryManifestKind::Candidate => names.0,
        RecoveryManifestKind::Plan => names.1,
        RecoveryManifestKind::Published => names.2,
    };
    root.read_private_named(&name, maximum)
        .map_err(RecoveryManifestError::from_descriptor)
}

fn recovery_manifest_remove_at_root(
    root: &PrivateDir,
    candidate_name: &str,
    kind: &str,
) -> RecoveryManifestResult<bool> {
    let names = recovery_manifest_names(candidate_name)?;
    let name = match RecoveryManifestKind::parse(kind)? {
        RecoveryManifestKind::Candidate => names.0,
        RecoveryManifestKind::Plan => names.1,
        RecoveryManifestKind::Published => {
            return Err(RecoveryManifestError::new(
                "invalid_kind",
                "durable published manifests cannot be removed through the Lua API",
            ))
        }
    };
    root.remove_private_verified(&name)
        .map_err(RecoveryManifestError::from_descriptor)
}

fn recovery_manifest_root() -> RecoveryManifestResult<PrivateDir> {
    let base_path = platform_data_base()?;
    recovery_manifest_root_at_base(&base_path)
}

fn recovery_manifest_root_at_base(base_path: &Path) -> RecoveryManifestResult<PrivateDir> {
    let base = PrivateDir::open_platform_base(base_path)
        .map_err(RecoveryManifestError::from_descriptor)?;
    let dmux = base
        .ensure_child("dmux")
        .map_err(RecoveryManifestError::from_descriptor)?;
    dmux.ensure_child("recovery-manifests")
        .map_err(RecoveryManifestError::from_descriptor)
}

fn recovery_manifest_names(
    candidate_name: &str,
) -> RecoveryManifestResult<(String, String, String)> {
    let stem = candidate_name.strip_prefix(".capture-").ok_or_else(|| {
        RecoveryManifestError::new("invalid_name", "candidate_name must start with .capture-")
    })?;
    if stem.len() < 40 {
        return Err(RecoveryManifestError::new(
            "invalid_name",
            "candidate_name is truncated",
        ));
    }
    let (epoch, suffix) = stem.split_at(36);
    validate_uuid("candidate epoch", epoch).map_err(RecoveryManifestError::from_descriptor)?;
    let suffix = suffix.strip_prefix('-').ok_or_else(|| {
        RecoveryManifestError::new("invalid_name", "candidate epoch delimiter is missing")
    })?;
    let (unix, serial) = suffix.split_once('-').ok_or_else(|| {
        RecoveryManifestError::new("invalid_name", "candidate time/serial delimiter is missing")
    })?;
    if serial.contains('-') {
        return Err(RecoveryManifestError::new(
            "invalid_name",
            "candidate_name has trailing fields",
        ));
    }
    for (label, value) in [("unix time", unix), ("serial", serial)] {
        let parsed = value.parse::<u64>().map_err(|_| {
            RecoveryManifestError::new("invalid_name", format!("candidate {label} is not decimal"))
        })?;
        if parsed == 0 || parsed > MAX_JSON_INTEGER || parsed.to_string() != value {
            return Err(RecoveryManifestError::new(
                "invalid_name",
                format!("candidate {label} is not a canonical positive exact integer"),
            ));
        }
    }
    validate_component(candidate_name).map_err(RecoveryManifestError::from_descriptor)?;
    let plan = format!("{candidate_name}.plan");
    let published = format!("manifest-{stem}.json");
    validate_component(&plan).map_err(RecoveryManifestError::from_descriptor)?;
    validate_component(&published).map_err(RecoveryManifestError::from_descriptor)?;
    Ok((candidate_name.to_string(), plan, published))
}

fn platform_data_base() -> RecoveryManifestResult<PathBuf> {
    let path = match std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                RecoveryManifestError::new(
                    "data_unavailable",
                    "neither XDG_DATA_HOME nor HOME is set",
                )
            })?;
            PathBuf::from(home).join(".local/share")
        }
    };
    if !path.is_absolute() {
        return Err(RecoveryManifestError::new(
            "data_unavailable",
            "dmux data base must be absolute",
        ));
    }
    Ok(path)
}

fn publish_service_descriptor(request: PublishRequest) -> DescriptorResult<PublishedDescriptor> {
    if !SERVICE_BOOTSTRAP_CLAIMED.load(Ordering::Acquire) {
        return Err(DescriptorError::new(
            "bootstrap_required",
            "managed service config did not claim the early native bootstrap",
        ));
    }
    let state = SERVICE_BOOTSTRAP.get().ok_or_else(|| {
        DescriptorError::new(
            "bootstrap_required",
            "call dmux_service_bootstrap during service configuration before publication",
        )
    })?;
    state.revalidate()?;
    publish_service_descriptor_in(&state.base_path, &state.base, &state.runtime, request)
}

#[cfg(test)]
fn publish_service_descriptor_at_base(
    base_path: &Path,
    request: PublishRequest,
) -> DescriptorResult<PublishedDescriptor> {
    let base = PrivateDir::open_platform_base(base_path)?;
    let runtime = base.ensure_child(RUNTIME_DIR)?;
    publish_service_descriptor_in(base_path, &base, &runtime, request)
}

fn publish_service_descriptor_in(
    base_path: &Path,
    base: &PrivateDir,
    runtime: &PrivateDir,
    request: PublishRequest,
) -> DescriptorResult<PublishedDescriptor> {
    request.validate()?;
    let socket_path = runtime.display_path.join(SOCKET_FILE);
    let socket = match socket_witness(runtime, false)? {
        Some(witness) => {
            if witness.peer_pid != std::process::id() {
                return Err(DescriptorError::new(
                    "socket_identity",
                    format!(
                        "fixed socket peer pid {} is not publisher pid {}",
                        witness.peer_pid,
                        std::process::id()
                    ),
                ));
            }
            Some(witness)
        }
        None if request.state == "ready" => {
            return Err(DescriptorError::new(
                "socket_unavailable",
                "ready publication requires the fixed live service socket",
            ));
        }
        None => None,
    };
    let pid = std::process::id();
    let descriptor = ServiceDescriptor {
        descriptor_version: DESCRIPTOR_VERSION,
        state: request.state,
        epoch: request.epoch,
        pid,
        socket: path_to_descriptor_string(&socket_path)?,
        socket_dev: socket.map(|witness| witness.dev),
        socket_ino: socket.map(|witness| witness.ino),
        start_token: process_start_token(pid)?,
        backend_instance_uid: request.backend_instance_uid,
        boot_nonce: request.boot_nonce,
        boot_id: current_boot_id()?,
        written_by: "mux-startup".to_string(),
        written_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        sentinel_window_id: request.sentinel_window_id,
        sentinel_tab_id: request.sentinel_tab_id,
        sentinel_pane_id: request.sentinel_pane_id,
        sentinel_fallback: request.sentinel_fallback,
        recovery_generation: request.recovery_generation,
        recovery_manifest_id: request.recovery_manifest_id,
        error: request.error,
    };
    if let Some(before) = socket {
        let after = socket_witness(runtime, true)?.ok_or_else(|| {
            DescriptorError::new(
                "socket_changed",
                "fixed socket disappeared before publication",
            )
        })?;
        if before != after {
            return Err(DescriptorError::new(
                "socket_changed",
                "fixed socket identity changed before publication",
            ));
        }
    }
    let mut raw = serde_json::to_vec(&descriptor)
        .map_err(|error| DescriptorError::new("invalid_descriptor", error.to_string()))?;
    raw.push(b'\n');
    runtime.publish_replace(&raw)?;
    revalidate_runtime_path(base_path, base, runtime)?;
    if let Some(before) = socket {
        let after = socket_witness(runtime, true)?.ok_or_else(|| {
            DescriptorError::new(
                "socket_changed",
                "fixed socket disappeared after publication",
            )
        })?;
        if before != after {
            return Err(DescriptorError::new(
                "socket_changed",
                "fixed socket identity changed after publication",
            ));
        }
    }
    Ok(PublishedDescriptor {
        descriptor,
        raw,
        peer_pid: socket.map(|witness| witness.peer_pid),
    })
}

/// Read the fixed descriptor only after proving that it names the current
/// boot, exact live server process incarnation, and exact fixed socket/peer.
pub fn read_verified_descriptor(maximum: usize) -> DescriptorResult<Option<Vec<u8>>> {
    let base_path = platform_runtime_base()?;
    read_verified_descriptor_at_base(&base_path, maximum)
}

fn read_verified_descriptor_at_base(
    base_path: &Path,
    maximum: usize,
) -> DescriptorResult<Option<Vec<u8>>> {
    if maximum == 0 || maximum > MAX_DESCRIPTOR_BYTES {
        return Err(DescriptorError::new(
            "invalid_limit",
            format!("descriptor limit must be between 1 and {MAX_DESCRIPTOR_BYTES}"),
        ));
    }
    let base = PrivateDir::open_platform_base(base_path)?;
    let runtime = base.child(RUNTIME_DIR)?;
    let Some(mut held_descriptor) = runtime.open_private_optional(DESCRIPTOR_FILE)? else {
        return Ok(None);
    };
    let descriptor_metadata = held_descriptor.metadata().map_err(|error| {
        DescriptorError::io(
            "read_failed",
            runtime.display_path.join(DESCRIPTOR_FILE).display(),
            error,
        )
    })?;
    let raw = read_held_bounded(
        &mut held_descriptor,
        &runtime.display_path.join(DESCRIPTOR_FILE),
        maximum,
    )?;
    let descriptor: ServiceDescriptor = serde_json::from_slice(&raw)
        .map_err(|error| DescriptorError::new("invalid_descriptor", error.to_string()))?;
    validate_ready_descriptor(&descriptor, &runtime)?;

    let expected_boot = current_boot_id()?;
    if descriptor.boot_id != expected_boot {
        return Err(DescriptorError::new(
            "stale_boot",
            "descriptor boot_id is not the running operating-system boot",
        ));
    }
    let expected_start = process_start_token(descriptor.pid)?;
    if descriptor.start_token != expected_start {
        return Err(DescriptorError::new(
            "stale_process",
            "descriptor start_token does not match the live pid incarnation",
        ));
    }
    let socket_before = socket_witness(&runtime, true)?.ok_or_else(|| {
        DescriptorError::new("socket_unavailable", "fixed descriptor socket is absent")
    })?;
    if socket_before.dev != descriptor.socket_dev.expect("validated")
        || socket_before.ino != descriptor.socket_ino.expect("validated")
    {
        return Err(DescriptorError::new(
            "socket_identity",
            "descriptor socket dev/inode does not match the fixed live socket",
        ));
    }
    if socket_before.peer_pid != descriptor.pid {
        return Err(DescriptorError::new(
            "socket_identity",
            format!(
                "fixed socket peer pid {} does not match descriptor pid {}",
                socket_before.peer_pid, descriptor.pid
            ),
        ));
    }

    // Recheck every replaceable witness while the peer connection proof has
    // just completed.  The returned bytes are from the held descriptor inode.
    if current_boot_id()? != descriptor.boot_id
        || process_start_token(descriptor.pid)? != descriptor.start_token
    {
        return Err(DescriptorError::new(
            "identity_changed",
            "boot or process incarnation changed during descriptor verification",
        ));
    }
    let socket_after = socket_witness(&runtime, true)?.ok_or_else(|| {
        DescriptorError::new(
            "socket_changed",
            "fixed socket disappeared during verification",
        )
    })?;
    if socket_after != socket_before {
        return Err(DescriptorError::new(
            "socket_changed",
            "fixed socket identity changed during descriptor verification",
        ));
    }
    revalidate_runtime_path(base_path, &base, &runtime)?;
    let current_descriptor = runtime
        .open_private_optional(DESCRIPTOR_FILE)?
        .ok_or_else(|| DescriptorError::new("descriptor_changed", "descriptor disappeared"))?;
    let current_metadata = current_descriptor
        .metadata()
        .map_err(|error| DescriptorError::io("descriptor_changed", DESCRIPTOR_FILE, error))?;
    if descriptor_metadata.dev() != current_metadata.dev()
        || descriptor_metadata.ino() != current_metadata.ino()
    {
        return Err(DescriptorError::new(
            "descriptor_changed",
            "descriptor path no longer names the held inode",
        ));
    }
    held_descriptor
        .seek(SeekFrom::Start(0))
        .map_err(|error| DescriptorError::io("descriptor_changed", DESCRIPTOR_FILE, error))?;
    let final_raw = read_held_bounded(
        &mut held_descriptor,
        &runtime.display_path.join(DESCRIPTOR_FILE),
        maximum,
    )?;
    if final_raw != raw {
        return Err(DescriptorError::new(
            "descriptor_changed",
            "descriptor bytes changed during verification",
        ));
    }
    Ok(Some(raw))
}

fn validate_ready_descriptor(
    descriptor: &ServiceDescriptor,
    runtime: &PrivateDir,
) -> DescriptorResult<()> {
    if descriptor.descriptor_version != DESCRIPTOR_VERSION || descriptor.state != "ready" {
        return Err(DescriptorError::new(
            "not_ready",
            "descriptor must be strict version 1 in ready state",
        ));
    }
    for (name, value) in [
        ("epoch", &descriptor.epoch),
        ("boot_nonce", &descriptor.boot_nonce),
    ] {
        validate_uuid(name, value)?;
    }
    validate_uuid(
        "backend_instance_uid",
        descriptor.backend_instance_uid.as_deref().ok_or_else(|| {
            DescriptorError::new(
                "invalid_descriptor",
                "ready descriptor lacks backend_instance_uid",
            )
        })?,
    )?;
    let expected_socket = path_to_descriptor_string(&runtime.display_path.join(SOCKET_FILE))?;
    if descriptor.socket != expected_socket {
        return Err(DescriptorError::new(
            "socket_identity",
            "descriptor socket is not the internally resolved fixed socket path",
        ));
    }
    if descriptor.pid == 0 || descriptor.pid > libc::pid_t::MAX as u32 {
        return Err(DescriptorError::new(
            "invalid_descriptor",
            "descriptor pid is outside the native process-id range",
        ));
    }
    for (name, value) in [
        ("socket_dev", descriptor.socket_dev),
        ("socket_ino", descriptor.socket_ino),
    ] {
        if !matches!(value, Some(1..=MAX_JSON_INTEGER)) {
            return Err(DescriptorError::new(
                "invalid_descriptor",
                format!("{name} is not a positive exact JSON/Lua integer"),
            ));
        }
    }
    if descriptor.written_by != "mux-startup"
        || descriptor.written_at.len() != 20
        || !descriptor.written_at.is_ascii()
    {
        return Err(DescriptorError::new(
            "invalid_descriptor",
            "descriptor writer witness is invalid",
        ));
    }
    if descriptor.sentinel_window_id.is_none()
        || descriptor.sentinel_tab_id.is_none()
        || descriptor.sentinel_pane_id.is_none()
        || descriptor.sentinel_fallback != Some(false)
        || descriptor.error.is_some()
    {
        return Err(DescriptorError::new(
            "invalid_descriptor",
            "ready descriptor lacks the non-fallback sentinel witness",
        ));
    }
    for value in [
        descriptor.sentinel_window_id,
        descriptor.sentinel_tab_id,
        descriptor.sentinel_pane_id,
    ] {
        if value.is_some_and(|value| value > MAX_JSON_INTEGER) {
            return Err(DescriptorError::new(
                "invalid_descriptor",
                "sentinel id exceeds the exact JSON/Lua integer range",
            ));
        }
    }
    if let Some(generation) = &descriptor.recovery_generation {
        validate_uuid("recovery_generation", generation)?;
    }
    if let Some(manifest) = &descriptor.recovery_manifest_id {
        validate_bounded_text("recovery_manifest_id", manifest, 256)?;
    }
    Ok(())
}

fn socket_witness(runtime: &PrivateDir, required: bool) -> DescriptorResult<Option<SocketWitness>> {
    let stat = match socket_stat(runtime)? {
        Some(stat) => stat,
        None if required => {
            return Err(DescriptorError::new(
                "socket_unavailable",
                "fixed socket is absent",
            ));
        }
        None => return Ok(None),
    };
    let socket_path = runtime.display_path.join(SOCKET_FILE);
    let connection = connect_unix_bounded(&socket_path)?;
    let peer_pid = peer_pid(&connection)?;
    let after = socket_stat(runtime)?.ok_or_else(|| {
        DescriptorError::new("socket_changed", "fixed socket disappeared after connect")
    })?;
    if stat != after {
        return Err(DescriptorError::new(
            "socket_changed",
            "fixed socket changed while connecting",
        ));
    }
    Ok(Some(SocketWitness {
        dev: stat.0,
        ino: stat.1,
        peer_pid,
    }))
}

fn socket_stat(runtime: &PrivateDir) -> DescriptorResult<Option<(u64, u64)>> {
    socket_stat_named(runtime, SOCKET_FILE)
}

fn socket_stat_named(
    runtime: &PrivateDir,
    file_name: &str,
) -> DescriptorResult<Option<(u64, u64)>> {
    validate_component(file_name)?;
    let name = CString::new(file_name).expect("validated component");
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            runtime.file.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(DescriptorError::io(
            "socket_unavailable",
            runtime.display_path.join(file_name).display(),
            error,
        ));
    }
    let kind = stat.st_mode & libc::S_IFMT;
    let mode = stat.st_mode & 0o777;
    if kind != libc::S_IFSOCK
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_nlink != 1
        || mode & 0o077 != 0
    {
        return Err(DescriptorError::new(
            "unsafe_socket",
            format!(
                "{} must be a singly-linked current-user-owned private Unix socket",
                runtime.display_path.join(file_name).display()
            ),
        ));
    }
    let dev = stat.st_dev as u64;
    let ino = stat.st_ino as u64;
    if dev == 0 || ino == 0 || dev > MAX_JSON_INTEGER || ino > MAX_JSON_INTEGER {
        return Err(DescriptorError::new(
            "unsafe_socket",
            "socket device/inode cannot be represented exactly in JSON/Lua",
        ));
    }
    Ok(Some((dev, ino)))
}

fn quarantine_socket(runtime: &PrivateDir, expected: (u64, u64)) -> DescriptorResult<()> {
    let quarantine = format!(".stale-socket-{}", Uuid::new_v4());
    let source = CString::new(SOCKET_FILE).expect("static component");
    let destination = CString::new(quarantine.as_str()).expect("generated component");
    if rename_noreplace(
        runtime.file.as_raw_fd(),
        &source,
        runtime.file.as_raw_fd(),
        &destination,
    ) != 0
    {
        return Err(DescriptorError::io(
            "socket_changed",
            runtime.display_path.join(SOCKET_FILE).display(),
            io::Error::last_os_error(),
        ));
    }
    let moved = socket_stat_named(runtime, &quarantine)?;
    if moved != Some(expected) {
        let _ = rename_noreplace(
            runtime.file.as_raw_fd(),
            &destination,
            runtime.file.as_raw_fd(),
            &source,
        );
        return Err(DescriptorError::new(
            "socket_changed",
            "atomic stale-socket quarantine moved a different inode",
        ));
    }
    // The unique quarantine entry is intentionally retained.  Unlinking by
    // name after verification would reintroduce a same-UID swap/delete race.
    sync_directory(&runtime.file)
}

fn connect_unix_bounded(path: &Path) -> DescriptorResult<File> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() {
        return Err(DescriptorError::new(
            "socket_unavailable",
            "fixed socket path exceeds sockaddr_un",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(DescriptorError::io(
            "socket_unavailable",
            "socket(AF_UNIX)",
            io::Error::last_os_error(),
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(DescriptorError::io(
            "socket_unavailable",
            "fcntl(service socket)",
            io::Error::last_os_error(),
        ));
    }
    let rc = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        ) {
            return Err(DescriptorError::io(
                "socket_unavailable",
                path.display(),
                error,
            ));
        }
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DescriptorError::new(
                    "socket_unavailable",
                    "timed out connecting to fixed socket",
                ));
            }
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
            let polled = unsafe { libc::poll(&mut pollfd, 1, timeout) };
            if polled > 0 {
                break;
            }
            if polled == 0 {
                return Err(DescriptorError::new(
                    "socket_unavailable",
                    "timed out connecting to fixed socket",
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(DescriptorError::io(
                    "socket_unavailable",
                    "poll(fixed socket)",
                    error,
                ));
            }
        }
        let mut socket_error: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(DescriptorError::io(
                "socket_unavailable",
                "getsockopt(SO_ERROR)",
                io::Error::last_os_error(),
            ));
        }
        if socket_error != 0 {
            return Err(DescriptorError::io(
                "socket_unavailable",
                path.display(),
                io::Error::from_raw_os_error(socket_error),
            ));
        }
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn peer_pid(socket: &File) -> DescriptorResult<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(DescriptorError::io(
            "socket_identity",
            "getsockopt(SO_PEERCRED)",
            io::Error::last_os_error(),
        ));
    }
    if length as usize != std::mem::size_of::<libc::ucred>()
        || credentials.pid <= 0
        || credentials.uid != unsafe { libc::geteuid() }
    {
        return Err(DescriptorError::new(
            "socket_identity",
            "socket peer credentials are incomplete or not current-user-owned",
        ));
    }
    Ok(credentials.pid as u32)
}

#[cfg(target_os = "macos")]
fn peer_pid(socket: &File) -> DescriptorResult<u32> {
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(DescriptorError::io(
            "socket_identity",
            "getsockopt(LOCAL_PEERPID)",
            io::Error::last_os_error(),
        ));
    }
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(DescriptorError::io(
            "socket_identity",
            "getpeereid",
            io::Error::last_os_error(),
        ));
    }
    if pid <= 0 || uid != unsafe { libc::geteuid() } {
        return Err(DescriptorError::new(
            "socket_identity",
            "socket peer is not a live current-user process",
        ));
    }
    Ok(pid as u32)
}

#[cfg(target_os = "linux")]
fn current_boot_id() -> DescriptorResult<String> {
    let raw = read_system_file_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
    let value = std::str::from_utf8(&raw)
        .map_err(|error| DescriptorError::new("identity_unavailable", error.to_string()))?
        .trim();
    validate_uuid("boot_id", value)?;
    Ok(format!("linux:{value}"))
}

#[cfg(target_os = "macos")]
fn current_boot_id() -> DescriptorResult<String> {
    let name = CString::new("kern.boottime").expect("static sysctl name");
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&value);
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut libc::timeval).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length != std::mem::size_of::<libc::timeval>()
        || value.tv_sec <= 0
        || !(0..=999_999).contains(&value.tv_usec)
    {
        return Err(DescriptorError::io(
            "identity_unavailable",
            "sysctlbyname(kern.boottime)",
            io::Error::last_os_error(),
        ));
    }
    Ok(format!("macos:{}:{}", value.tv_sec, value.tv_usec))
}

#[cfg(target_os = "linux")]
pub fn process_start_token(pid: u32) -> DescriptorResult<String> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return Err(DescriptorError::new(
            "identity_unavailable",
            "pid is outside the native process-id range",
        ));
    }
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let metadata = std::fs::metadata(&proc_dir)
        .map_err(|error| DescriptorError::io("identity_unavailable", proc_dir.display(), error))?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(DescriptorError::new(
            "identity_unavailable",
            "descriptor process is not current-user-owned",
        ));
    }
    let stat_path = proc_dir.join("stat");
    let raw = read_system_file_bounded(&stat_path, 4096)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|error| DescriptorError::new("identity_unavailable", error.to_string()))?;
    let (prefix, suffix) = text.rsplit_once(") ").ok_or_else(|| {
        DescriptorError::new("identity_unavailable", "malformed Linux process stat")
    })?;
    let actual_pid: u32 = prefix
        .split_once('(')
        .ok_or_else(|| DescriptorError::new("identity_unavailable", "malformed process pid"))?
        .0
        .trim()
        .parse()
        .map_err(|_| DescriptorError::new("identity_unavailable", "malformed process pid"))?;
    if actual_pid != pid {
        return Err(DescriptorError::new(
            "identity_unavailable",
            "Linux process stat pid changed",
        ));
    }
    let fields: Vec<&str> = suffix.split_whitespace().collect();
    let ticks: u64 = fields
        .get(19)
        .ok_or_else(|| DescriptorError::new("identity_unavailable", "process stat is truncated"))?
        .parse()
        .map_err(|_| DescriptorError::new("identity_unavailable", "invalid process start ticks"))?;
    if ticks == 0 || ticks > MAX_JSON_INTEGER {
        return Err(DescriptorError::new(
            "identity_unavailable",
            "process start ticks are outside the exact identity range",
        ));
    }
    Ok(format!("linux:{ticks}"))
}

#[cfg(target_os = "macos")]
pub fn process_start_token(pid: u32) -> DescriptorResult<String> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return Err(DescriptorError::new(
            "identity_unavailable",
            "pid is outside the native process-id range",
        ));
    }
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let wanted = std::mem::size_of_val(&info) as libc::c_int;
    let actual = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            wanted,
        )
    };
    if actual != wanted
        || info.pbi_pid != pid
        || info.pbi_uid != unsafe { libc::geteuid() }
        || info.pbi_start_tvsec == 0
        || info.pbi_start_tvusec > 999_999
    {
        return Err(DescriptorError::new(
            "identity_unavailable",
            format!("cannot identify current-user process {pid}"),
        ));
    }
    Ok(format!(
        "macos:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(target_os = "linux")]
fn read_system_file_bounded(path: &Path, maximum: usize) -> DescriptorResult<Vec<u8>> {
    let mut file = File::open(path)
        .map_err(|error| DescriptorError::io("identity_unavailable", path.display(), error))?;
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| DescriptorError::io("identity_unavailable", path.display(), error))?;
    if bytes.len() > maximum {
        return Err(DescriptorError::new(
            "identity_unavailable",
            format!("{} is oversized", path.display()),
        ));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn platform_runtime_base() -> DescriptorResult<PathBuf> {
    let path = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| DescriptorError::new("runtime_unavailable", "XDG_RUNTIME_DIR is not set"))?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(DescriptorError::new(
            "runtime_unavailable",
            "XDG_RUNTIME_DIR must be absolute",
        ));
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn platform_runtime_base() -> DescriptorResult<PathBuf> {
    let mut bytes = vec![0u8; 1024];
    loop {
        let required = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if required == 0 {
            return Err(DescriptorError::io(
                "runtime_unavailable",
                "confstr(_CS_DARWIN_USER_TEMP_DIR)",
                io::Error::last_os_error(),
            ));
        }
        if required <= bytes.len() {
            bytes.truncate(required.saturating_sub(1));
            let path = PathBuf::from(OsString::from_vec(bytes));
            if !path.is_absolute() {
                return Err(DescriptorError::new(
                    "runtime_unavailable",
                    "_CS_DARWIN_USER_TEMP_DIR is not absolute",
                ));
            }
            return Ok(path);
        }
        bytes.resize(required, 0);
    }
}

fn validate_directory(file: &File, path: &Path, exact_mode: Option<u32>) -> DescriptorResult<()> {
    let metadata = file
        .metadata()
        .map_err(|error| DescriptorError::io("unsafe_directory", path.display(), error))?;
    let mode = metadata.mode() & 0o777;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || exact_mode.is_some_and(|exact| mode != exact)
        || exact_mode.is_none() && mode & 0o022 != 0
    {
        return Err(DescriptorError::new(
            "unsafe_directory",
            format!(
                "{} is not a verified private current-user directory",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validate_private_file(file: &File, path: &Path) -> DescriptorResult<()> {
    let metadata = file
        .metadata()
        .map_err(|error| DescriptorError::io("unsafe_file", path.display(), error))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(DescriptorError::new(
            "unsafe_file",
            format!(
                "{} must be a singly-linked current-user-owned mode-0600 regular file",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validate_component(name: &str) -> DescriptorResult<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.bytes().any(|byte| byte == 0 || byte == b'/')
    {
        return Err(DescriptorError::new(
            "invalid_path",
            "unsafe fixed-path component",
        ));
    }
    Ok(())
}

fn validate_uuid(name: &str, value: &str) -> DescriptorResult<()> {
    let parsed = value
        .parse::<Uuid>()
        .map_err(|_| DescriptorError::new("invalid_descriptor", format!("{name} is not a UUID")))?;
    if parsed.to_string() != value {
        return Err(DescriptorError::new(
            "invalid_descriptor",
            format!("{name} is not a canonical lowercase UUID"),
        ));
    }
    Ok(())
}

fn validate_bounded_text(name: &str, value: &str, maximum: usize) -> DescriptorResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte < b' ' || byte == 0x7f)
    {
        return Err(DescriptorError::new(
            "invalid_descriptor",
            format!("{name} is empty, oversized, or contains control bytes"),
        ));
    }
    Ok(())
}

fn path_to_descriptor_string(path: &Path) -> DescriptorResult<String> {
    let value = path
        .to_str()
        .ok_or_else(|| DescriptorError::new("invalid_path", "fixed socket path is not UTF-8"))?;
    if value.as_bytes().contains(&0) {
        return Err(DescriptorError::new(
            "invalid_path",
            "fixed socket path contains NUL",
        ));
    }
    Ok(value.to_string())
}

fn read_held_bounded(file: &mut File, path: &Path, maximum: usize) -> DescriptorResult<Vec<u8>> {
    validate_private_file(file, path)?;
    let before = file
        .metadata()
        .map_err(|error| DescriptorError::io("read_failed", path.display(), error))?;
    if before.len() > maximum as u64 {
        return Err(DescriptorError::new(
            "message_too_large",
            format!("{} exceeds {maximum} bytes", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(file)
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| DescriptorError::io("read_failed", path.display(), error))?;
    let after = file
        .metadata()
        .map_err(|error| DescriptorError::io("read_failed", path.display(), error))?;
    if bytes.len() > maximum || before.len() != after.len() || bytes.len() as u64 != after.len() {
        return Err(DescriptorError::new(
            "descriptor_changed",
            format!("{} changed while being read", path.display()),
        ));
    }
    Ok(bytes)
}

fn revalidate_runtime_path(
    base_path: &Path,
    held_base: &PrivateDir,
    held_runtime: &PrivateDir,
) -> DescriptorResult<()> {
    let current_base = PrivateDir::open_platform_base(base_path)?;
    let current_runtime = current_base.child(RUNTIME_DIR)?;
    for (label, held, current) in [
        ("runtime base", &held_base.file, &current_base.file),
        ("dmux runtime", &held_runtime.file, &current_runtime.file),
    ] {
        let held_metadata = held
            .metadata()
            .map_err(|error| DescriptorError::io("runtime_changed", label, error))?;
        let current_metadata = current
            .metadata()
            .map_err(|error| DescriptorError::io("runtime_changed", label, error))?;
        if held_metadata.dev() != current_metadata.dev()
            || held_metadata.ino() != current_metadata.ino()
        {
            return Err(DescriptorError::new(
                "runtime_changed",
                format!("{label} path changed during operation"),
            ));
        }
    }
    Ok(())
}

fn sync_directory(file: &File) -> DescriptorResult<()> {
    if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(DescriptorError::io(
            "sync_failed",
            "descriptor directory",
            io::Error::last_os_error(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn rename_noreplace(
    old_dir: libc::c_int,
    old_name: &CString,
    new_dir: libc::c_int,
    new_name: &CString,
) -> libc::c_int {
    unsafe {
        libc::renameat2(
            old_dir,
            old_name.as_ptr(),
            new_dir,
            new_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(
    old_dir: libc::c_int,
    old_name: &CString,
    new_dir: libc::c_int,
    new_name: &CString,
) -> libc::c_int {
    unsafe {
        libc::renameatx_np(
            old_dir,
            old_name.as_ptr(),
            new_dir,
            new_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    fn base() -> tempfile::TempDir {
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        base
    }

    fn request(state: &str) -> PublishRequest {
        PublishRequest {
            state: state.to_string(),
            epoch: "11111111-1111-4111-8111-111111111111".to_string(),
            backend_instance_uid: Some("22222222-2222-4222-8222-222222222222".to_string()),
            boot_nonce: "33333333-3333-4333-8333-333333333333".to_string(),
            sentinel_window_id: (state == "ready").then_some(0),
            sentinel_tab_id: (state == "ready").then_some(0),
            sentinel_pane_id: (state == "ready").then_some(0),
            sentinel_fallback: (state == "ready").then_some(false),
            recovery_generation: None,
            recovery_manifest_id: None,
            error: None,
        }
    }

    fn listener(base: &Path) -> UnixListener {
        let root = PrivateDir::open_platform_base(base).unwrap();
        let runtime = root.ensure_child(RUNTIME_DIR).unwrap();
        let listener = UnixListener::bind(runtime.display_path.join(SOCKET_FILE)).unwrap();
        fs::set_permissions(
            runtime.display_path.join(SOCKET_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        listener
    }

    #[test]
    fn early_service_bind_is_relative_private_and_restores_cwd() {
        let base = base();
        let before = std::env::current_dir().unwrap();
        let state = ServiceBootstrap::initialize_at_base(base.path()).unwrap();
        let listener = bind_service_socket_early(&state).unwrap();
        assert_eq!(std::env::current_dir().unwrap(), before);
        let witness = socket_witness(&state.runtime, true).unwrap().unwrap();
        assert_eq!(witness.peer_pid, std::process::id());
        assert_eq!(state.bound_socket, None);
        let metadata =
            fs::symlink_metadata(base.path().join(RUNTIME_DIR).join(SOCKET_FILE)).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o077, 0);
        drop(listener);
    }

    #[test]
    fn early_service_bind_refuses_live_and_quarantines_only_proven_stale_socket() {
        let live_base = base();
        let live = listener(live_base.path());
        let error = ServiceBootstrap::initialize_at_base(live_base.path())
            .err()
            .unwrap();
        assert_eq!(error.code(), "duplicate_service");
        assert!(live_base
            .path()
            .join(RUNTIME_DIR)
            .join(SOCKET_FILE)
            .exists());
        drop(live);

        let stale_base = base();
        let first = ServiceBootstrap::initialize_at_base(stale_base.path()).unwrap();
        let stale = bind_service_socket_early(&first).unwrap();
        drop(stale);
        drop(first);

        let second = ServiceBootstrap::initialize_at_base(stale_base.path()).unwrap();
        assert!(!stale_base
            .path()
            .join(RUNTIME_DIR)
            .join(SOCKET_FILE)
            .exists());
        let quarantined = fs::read_dir(stale_base.path().join(RUNTIME_DIR))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stale-socket-")
            })
            .count();
        assert_eq!(quarantined, 1);
        let replacement = bind_service_socket_early(&second).unwrap();
        assert!(stale_base
            .path()
            .join(RUNTIME_DIR)
            .join(SOCKET_FILE)
            .exists());
        drop(replacement);
    }

    #[test]
    fn early_service_bind_rejects_runtime_path_replacement_before_side_effect() {
        let base = base();
        let state = ServiceBootstrap::initialize_at_base(base.path()).unwrap();
        let runtime = base.path().join(RUNTIME_DIR);
        let held = base.path().join("held-runtime");
        fs::rename(&runtime, &held).unwrap();
        let target = base.path().join("replacement-target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &runtime).unwrap();

        let error = bind_service_socket_early(&state).err().unwrap();
        assert!(matches!(
            error.code(),
            "unsafe_directory" | "runtime_changed"
        ));
        assert!(!target.join(SOCKET_FILE).exists());
        assert!(!held.join(SOCKET_FILE).exists());
    }

    fn replace_descriptor(base: &Path, descriptor: &ServiceDescriptor) {
        let root = PrivateDir::open_platform_base(base).unwrap();
        let runtime = root.child(RUNTIME_DIR).unwrap();
        let mut raw = serde_json::to_vec(descriptor).unwrap();
        raw.push(b'\n');
        runtime.publish_replace(&raw).unwrap();
    }

    #[test]
    fn starting_publication_is_private_atomic_and_rejects_preplants() {
        let base = base();
        let published =
            publish_service_descriptor_at_base(base.path(), request("starting")).unwrap();
        assert_eq!(published.descriptor.state, "starting");
        assert_eq!(published.descriptor.socket_dev, None);
        let descriptor_path = base.path().join(RUNTIME_DIR).join(DESCRIPTOR_FILE);
        assert_eq!(
            fs::metadata(&descriptor_path).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&descriptor_path).unwrap(), published.raw);

        fs::remove_file(&descriptor_path).unwrap();
        let target = base.path().join("preplant-target");
        fs::write(&target, b"must-not-change").unwrap();
        symlink(&target, &descriptor_path).unwrap();
        let error =
            publish_service_descriptor_at_base(base.path(), request("starting")).unwrap_err();
        assert_eq!(error.code(), "unsafe_file");
        assert_eq!(fs::read(target).unwrap(), b"must-not-change");
    }

    #[test]
    fn ready_round_trip_proves_boot_process_and_socket_identity() {
        let base = base();
        let _listener = listener(base.path());
        let published = publish_service_descriptor_at_base(base.path(), request("ready")).unwrap();
        assert_eq!(published.peer_pid, Some(std::process::id()));
        assert_eq!(
            published.descriptor.start_token,
            process_start_token(std::process::id()).unwrap()
        );
        assert_eq!(published.descriptor.boot_id, current_boot_id().unwrap());
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap()
                .unwrap(),
            published.raw
        );
    }

    #[test]
    fn mux_startup_style_repeated_publication_does_not_wait_for_accept() {
        let base = base();
        // The listener deliberately remains on this callback thread and is
        // never accepted.  This models mux-startup, where recursively calling
        // the mux CLI would deadlock because the event loop cannot service
        // itself.  The native bounded connect must only queue and return.
        let _listener = listener(base.path());
        let began = Instant::now();
        for state in ["starting", "recovering", "ready"] {
            let published =
                publish_service_descriptor_at_base(base.path(), request(state)).unwrap();
            assert_eq!(published.descriptor.state, state);
            assert_eq!(published.peer_pid, Some(std::process::id()));
        }
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "native mux-startup publication unexpectedly blocked"
        );
        let raw = read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
            .unwrap()
            .unwrap();
        let descriptor: ServiceDescriptor = serde_json::from_slice(&raw).unwrap();
        assert_eq!(descriptor.state, "ready");
    }

    #[test]
    fn stale_boot_pid_start_and_socket_witnesses_fail_closed() {
        let base = base();
        let _listener = listener(base.path());
        let published = publish_service_descriptor_at_base(base.path(), request("ready")).unwrap();

        let mut stale = published.descriptor.clone();
        stale.boot_id = match current_boot_id().unwrap().split_once(':').unwrap().0 {
            "linux" => "linux:44444444-4444-4444-8444-444444444444".to_string(),
            _ => "macos:1:0".to_string(),
        };
        replace_descriptor(base.path(), &stale);
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "stale_boot"
        );

        let mut stale = published.descriptor.clone();
        stale.start_token = if cfg!(target_os = "linux") {
            "linux:1".to_string()
        } else {
            "macos:1:0".to_string()
        };
        replace_descriptor(base.path(), &stale);
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "stale_process"
        );

        let mut stale = published.descriptor.clone();
        stale.pid = libc::pid_t::MAX as u32;
        replace_descriptor(base.path(), &stale);
        assert!(matches!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "identity_unavailable" | "stale_process"
        ));

        let mut stale = published.descriptor;
        stale.socket_ino = stale.socket_ino.map(|ino| ino.saturating_add(1));
        replace_descriptor(base.path(), &stale);
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "socket_identity"
        );
    }

    #[test]
    fn socket_replacement_and_symlinked_runtime_fail_closed() {
        let primary_base = base();
        let listener = listener(primary_base.path());
        let published =
            publish_service_descriptor_at_base(primary_base.path(), request("ready")).unwrap();
        drop(listener);
        let socket_path = primary_base.path().join(RUNTIME_DIR).join(SOCKET_FILE);
        fs::remove_file(&socket_path).unwrap();
        let _replacement = UnixListener::bind(&socket_path).unwrap();
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_verified_descriptor_at_base(primary_base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "socket_identity"
        );
        assert_ne!(
            fs::symlink_metadata(&socket_path).unwrap().ino(),
            published.descriptor.socket_ino.unwrap()
        );

        let holder = base();
        let target = base();
        symlink(target.path(), holder.path().join(RUNTIME_DIR)).unwrap();
        assert_eq!(
            publish_service_descriptor_at_base(holder.path(), request("starting"))
                .unwrap_err()
                .code(),
            "unsafe_directory"
        );
    }

    #[test]
    fn strict_reader_rejects_unknown_fields_symlinks_and_bounds() {
        let base = base();
        let root = PrivateDir::open_platform_base(base.path()).unwrap();
        let runtime = root.ensure_child(RUNTIME_DIR).unwrap();
        runtime
            .publish_replace(br#"{"descriptor_version":1,"unknown":true}"#)
            .unwrap();
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "invalid_descriptor"
        );
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), 1)
                .unwrap_err()
                .code(),
            "message_too_large"
        );
        runtime.unlink(DESCRIPTOR_FILE).unwrap();
        let target = base.path().join("descriptor-target");
        fs::write(&target, b"hostile").unwrap();
        symlink(&target, runtime.display_path.join(DESCRIPTOR_FILE)).unwrap();
        assert_eq!(
            read_verified_descriptor_at_base(base.path(), MAX_DESCRIPTOR_BYTES)
                .unwrap_err()
                .code(),
            "unsafe_file"
        );
    }

    #[test]
    fn recovery_spool_is_fixed_private_bounded_and_atomic() {
        let base = base();
        let epoch = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let epoch_dir = recovery_epoch_dir_at_base(base.path(), epoch).unwrap();
        assert!(recovery_spool_read_from_dir(&epoch_dir, "command", 1024)
            .unwrap()
            .is_none());
        recovery_spool_write_to_dir(&epoch_dir, "command", b"first").unwrap();
        recovery_spool_write_to_dir(&epoch_dir, "command", b"second").unwrap();
        assert_eq!(
            recovery_spool_read_from_dir(&epoch_dir, "command", 1024)
                .unwrap()
                .unwrap(),
            b"second"
        );
        let file = epoch_dir
            .open_private_optional("command.json")
            .unwrap()
            .unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(recovery_spool_remove_from_dir(&epoch_dir, "command").unwrap());
        assert!(!recovery_spool_remove_from_dir(&epoch_dir, "command").unwrap());
        assert_eq!(
            recovery_spool_read_from_dir(&epoch_dir, "status", 0)
                .unwrap_err()
                .code,
            "invalid_limit"
        );
        assert_eq!(
            recovery_spool_write_to_dir(
                &epoch_dir,
                "response",
                &vec![0; MAX_RECOVERY_MESSAGE_BYTES + 1]
            )
            .unwrap_err()
            .code,
            "message_too_large"
        );
        assert_eq!(
            recovery_spool_read_from_dir(&epoch_dir, "../escape", 1024)
                .unwrap_err()
                .code,
            "invalid_kind"
        );
    }

    #[test]
    fn recovery_spool_rejects_symlink_preplants_and_unsafe_epoch_dirs() {
        let primary_base = base();
        let epoch = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let epoch_dir = recovery_epoch_dir_at_base(primary_base.path(), epoch).unwrap();
        let target = primary_base.path().join("spool-target");
        fs::write(&target, b"must-not-change").unwrap();
        symlink(&target, epoch_dir.display_path.join("control.json")).unwrap();
        assert_eq!(
            recovery_spool_write_to_dir(&epoch_dir, "control", b"hostile")
                .unwrap_err()
                .code,
            "unsafe_file"
        );
        assert_eq!(fs::read(&target).unwrap(), b"must-not-change");

        let hostile_base = base();
        let root = PrivateDir::open_platform_base(hostile_base.path()).unwrap();
        let runtime = root.ensure_child(RUNTIME_DIR).unwrap();
        let recovery = runtime.ensure_child("recovery").unwrap();
        fs::create_dir(recovery.display_path.join(epoch)).unwrap();
        fs::set_permissions(
            recovery.display_path.join(epoch),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert_eq!(
            recovery_epoch_dir_at_base(hostile_base.path(), epoch)
                .unwrap_err()
                .code,
            "unsafe_directory"
        );
    }

    #[test]
    fn recovery_remove_never_deletes_a_post_verification_name_swap() {
        let base = base();
        let epoch = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        let epoch_dir = recovery_epoch_dir_at_base(base.path(), epoch).unwrap();
        recovery_spool_write_to_dir(&epoch_dir, "command", b"original").unwrap();

        let mut replacement_path = None;
        assert!(epoch_dir
            .remove_private_verified_with_hook("command.json", |quarantine| {
                fs::remove_file(quarantine).unwrap();
                fs::write(quarantine, b"racing replacement").unwrap();
                fs::set_permissions(quarantine, fs::Permissions::from_mode(0o600)).unwrap();
                replacement_path = Some(quarantine.to_path_buf());
            })
            .unwrap());

        assert!(!epoch_dir.display_path.join("command.json").exists());
        let replacement_path = replacement_path.unwrap();
        assert_eq!(fs::read(replacement_path).unwrap(), b"racing replacement");
    }

    #[test]
    fn recovery_manifest_handle_uses_fixed_opaque_names_and_private_files() {
        let base = base();
        let root = recovery_manifest_root_at_base(base.path()).unwrap();
        let candidate = ".capture-11111111-1111-4111-8111-111111111111-1700000000-1";
        let names = recovery_manifest_names(candidate).unwrap();

        recovery_manifest_write_candidate_at_root(&root, candidate, b"candidate").unwrap();
        assert_eq!(
            recovery_manifest_read_at_root(&root, candidate, "candidate", 1024)
                .unwrap()
                .unwrap(),
            b"candidate"
        );
        let file = root.open_private_optional(&names.0).unwrap().unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);

        let above_spool_limit = vec![b'x'; MAX_RECOVERY_MESSAGE_BYTES + 1];
        recovery_manifest_write_candidate_at_root(&root, candidate, &above_spool_limit).unwrap();
        assert_eq!(
            recovery_manifest_read_at_root(
                &root,
                candidate,
                "candidate",
                MAX_RECOVERY_MANIFEST_BYTES,
            )
            .unwrap()
            .unwrap()
            .len(),
            MAX_RECOVERY_MESSAGE_BYTES + 1
        );
        assert_eq!(
            recovery_manifest_write_candidate_at_root(
                &root,
                candidate,
                &vec![0; MAX_RECOVERY_MANIFEST_BYTES + 1],
            )
            .unwrap_err()
            .code,
            "message_too_large"
        );

        root.publish_named_replace(&names.1, b"plan", MAX_RECOVERY_MANIFEST_BYTES)
            .unwrap();
        root.publish_named_replace(&names.2, b"published", MAX_RECOVERY_MANIFEST_BYTES)
            .unwrap();
        assert_eq!(
            recovery_manifest_read_at_root(&root, candidate, "plan", 1024)
                .unwrap()
                .unwrap(),
            b"plan"
        );
        assert_eq!(
            recovery_manifest_read_at_root(&root, candidate, "published", 1024)
                .unwrap()
                .unwrap(),
            b"published"
        );
        assert!(recovery_manifest_remove_at_root(&root, candidate, "candidate").unwrap());
        assert!(recovery_manifest_remove_at_root(&root, candidate, "plan").unwrap());
        assert_eq!(
            recovery_manifest_remove_at_root(&root, candidate, "published")
                .unwrap_err()
                .code,
            "invalid_kind"
        );
        assert!(recovery_manifest_names("../../escape").is_err());
        assert_eq!(
            recovery_manifest_read_at_root(&root, candidate, "candidate", 0)
                .unwrap_err()
                .code,
            "invalid_limit"
        );
    }

    #[test]
    fn recovery_manifest_rejects_symlink_preplants_and_unsafe_roots() {
        let primary = base();
        let root = recovery_manifest_root_at_base(primary.path()).unwrap();
        let candidate = ".capture-22222222-2222-4222-8222-222222222222-1700000000-2";
        let target = primary.path().join("manifest-target");
        fs::write(&target, b"must-not-change").unwrap();
        symlink(&target, root.display_path.join(candidate)).unwrap();
        assert_eq!(
            recovery_manifest_write_candidate_at_root(&root, candidate, b"hostile")
                .unwrap_err()
                .code,
            "unsafe_file"
        );
        assert_eq!(fs::read(target).unwrap(), b"must-not-change");

        let hostile = base();
        fs::create_dir(hostile.path().join("dmux")).unwrap();
        fs::set_permissions(
            hostile.path().join("dmux"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert_eq!(
            recovery_manifest_root_at_base(hostile.path())
                .unwrap_err()
                .code,
            "unsafe_directory"
        );
    }

    #[test]
    fn backend_identity_is_optional_only_for_unavailable_states() {
        let base = base();
        let mut starting = request("starting");
        starting.backend_instance_uid = None;
        let published = publish_service_descriptor_at_base(base.path(), starting).unwrap();
        assert_eq!(published.descriptor.backend_instance_uid, None);

        let mut failed = request("failed");
        failed.backend_instance_uid = None;
        failed.error = Some("managed service unavailable".to_string());
        publish_service_descriptor_at_base(base.path(), failed).unwrap();

        for state in ["recovering", "ready"] {
            let mut invalid = request(state);
            invalid.backend_instance_uid = None;
            assert_eq!(
                publish_service_descriptor_at_base(base.path(), invalid)
                    .unwrap_err()
                    .code(),
                "invalid_request"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_linux_runtime_environment_fails_closed() {
        const PROBE: &str = "DMUX_DESCRIPTOR_MISSING_XDG_PROBE";
        if std::env::var_os(PROBE).is_some() {
            assert_eq!(
                platform_runtime_base().unwrap_err().code(),
                "runtime_unavailable"
            );
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("dmux_descriptor::tests::missing_linux_runtime_environment_fails_closed")
            .arg("--test-threads=1")
            .env(PROBE, "1")
            .env_remove("XDG_RUNTIME_DIR")
            .env("DMUX_RUNTIME_DIR", "/attacker/runtime")
            .env("TMPDIR", "/attacker/tmp")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
