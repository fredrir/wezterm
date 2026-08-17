//! Descriptor-backed filesystem transport for the trusted dmux GUI bridge.
//!
//! The public Lua surface deliberately accepts only validated instance and
//! request identifiers.  Runtime paths and spool kinds are selected here,
//! after opening and retaining verified directory descriptors.  That keeps
//! configuration Lua away from path-based `io.open`, `os.rename`, and
//! environment-selected temporary directories for the bridge trust boundary.

use anyhow::Context;
use mlua::{Lua, String as LuaString, Table, UserData, UserDataMethods};
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use window::{Connection, ConnectionOps};

const API_VERSION: u32 = 1;
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_INSTANCE_BYTES: usize = 160;
const BRIDGE_DIR: &str = "bridge";
const INSTANCES_DIR: &str = "instances";
const KEY_FILE: &str = "key";
const LEASE_FILE: &str = ".consumer-lease";

const ENV_GUI_INSTANCE: &str = "DMUX_GUI_INSTANCE";
const ENV_LAUNCHER_REQUEST_UID: &str = "DMUX_GUI_LAUNCHER_REQUEST_UID";
const ENV_LAUNCHER_PID: &str = "DMUX_GUI_LAUNCHER_PID";
const ENV_LAUNCHER_START_TOKEN: &str = "DMUX_GUI_LAUNCHER_START_TOKEN";
const ENV_BACKEND_INSTANCE: &str = "DMUX_GUI_BACKEND_INSTANCE";
const ENV_TARGET_DOMAIN: &str = "DMUX_GUI_TARGET_DOMAIN";
const ENV_TARGET_BACKEND_INSTANCE: &str = "DMUX_GUI_TARGET_BACKEND_INSTANCE";
const ENV_TARGET_SERVER_EPOCH: &str = "DMUX_GUI_TARGET_SERVER_EPOCH";
const ENV_TARGET_HOST_UID: &str = "DMUX_GUI_TARGET_HOST_UID";
const ENV_TARGET_SPACE_UID: &str = "DMUX_GUI_TARGET_SPACE_UID";

lazy_static::lazy_static! {
    /// `flock` excludes other processes.  This set also excludes a second
    /// open of the same instance by one process/config generation.
    static ref ACTIVE_INSTANCE_LEASES: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    /// Durable markers prevent cross-restart replay; this set additionally
    /// makes the one-use property immediate within one process/config reload.
    static ref COMPLETED_LIFECYCLE_PROOFS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
}

static CAPTURED_LAUNCHER_WITNESS: OnceLock<CapturedLauncherWitness> = OnceLock::new();
static LAUNCHER_WITNESS_CONSUMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Eq, PartialEq)]
struct LauncherWitness {
    origin: LauncherOrigin,
    transport_backend_instance_uid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LauncherOrigin {
    gui_instance: String,
    uid: u64,
    pid: u32,
    start_token: String,
    launcher_request_uid: String,
    domain: String,
    backend_instance_uid: String,
    server_epoch: String,
    host_uid: String,
    space_uid: Option<String>,
}

#[derive(Debug)]
enum CapturedLauncherWitness {
    Absent,
    Present(LauncherWitness),
    Invalid(String),
}

#[derive(Debug)]
struct BridgeFsError {
    code: &'static str,
    detail: String,
}

impl BridgeFsError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn io(code: &'static str, context: impl fmt::Display, error: io::Error) -> Self {
        Self::new(code, format!("{context}: {error}"))
    }
}

impl fmt::Display for BridgeFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dmux_bridge_{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for BridgeFsError {}

type BridgeResult<T> = Result<T, BridgeFsError>;

fn luaerr(error: BridgeFsError) -> mlua::Error {
    mlua::Error::external(error)
}

#[derive(Debug)]
struct ActiveLeaseClaim {
    instance: String,
}

impl ActiveLeaseClaim {
    fn claim(instance: &str) -> BridgeResult<Self> {
        let mut active = ACTIVE_INSTANCE_LEASES.lock();
        if !active.insert(instance.to_string()) {
            return Err(BridgeFsError::new(
                "duplicate_instance",
                format!("GUI instance {instance:?} is already leased by this process"),
            ));
        }
        Ok(Self {
            instance: instance.to_string(),
        })
    }
}

impl Drop for ActiveLeaseClaim {
    fn drop(&mut self) {
        ACTIVE_INSTANCE_LEASES.lock().remove(&self.instance);
    }
}

/// One open, verified directory.  All descendants are opened relative to
/// this descriptor with `O_NOFOLLOW`; no operation reconstructs an absolute
/// path after the initial trusted platform runtime resolution.
#[derive(Debug)]
struct PrivateDir {
    file: File,
    display_path: PathBuf,
}

impl PrivateDir {
    fn open_platform_base(path: &Path) -> BridgeResult<Self> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            BridgeFsError::new("invalid_path", "platform runtime path contains NUL")
        })?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(BridgeFsError::io(
                "runtime_unavailable",
                path.display(),
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_dir(&file, path, None)?;
        Ok(Self {
            file,
            display_path: path.to_path_buf(),
        })
    }

    fn child(&self, name: &str) -> BridgeResult<Self> {
        validate_component(name)?;
        let c_name = CString::new(name).expect("validated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(BridgeFsError::io(
                "unsafe_directory",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let display_path = self.display_path.join(name);
        validate_dir(&file, &display_path, Some(0o700))?;
        Ok(Self { file, display_path })
    }

    fn ensure_child(&self, name: &str) -> BridgeResult<Self> {
        validate_component(name)?;
        let c_name = CString::new(name).expect("validated component");
        let rc = unsafe { libc::mkdirat(self.file.as_raw_fd(), c_name.as_ptr(), 0o700) };
        let created = if rc == 0 {
            true
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(BridgeFsError::io(
                    "create_directory",
                    self.display_path.join(name).display(),
                    error,
                ));
            }
            false
        };

        // Open first with no-follow.  Only a directory created by this call
        // may have its mode repaired after an unusually restrictive umask;
        // pre-existing wrong-mode entries are rejected, never chmod'd.
        let c_name = CString::new(name).expect("validated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(BridgeFsError::io(
                "unsafe_directory",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if created {
            let rc = unsafe { libc::fchmod(file.as_raw_fd(), 0o700) };
            if rc != 0 {
                return Err(BridgeFsError::io(
                    "create_directory",
                    self.display_path.join(name).display(),
                    io::Error::last_os_error(),
                ));
            }
        }
        let display_path = self.display_path.join(name);
        validate_dir(&file, &display_path, Some(0o700))?;
        if created {
            sync_directory(&self.file)?;
        }
        Ok(Self { file, display_path })
    }

    fn open_private_optional(&self, name: &str) -> BridgeResult<Option<File>> {
        validate_component(name)?;
        let c_name = CString::new(name).expect("validated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(BridgeFsError::io(
                "unsafe_file",
                self.display_path.join(name).display(),
                error,
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_file(&file, &self.display_path.join(name))?;
        Ok(Some(file))
    }

    fn read_private_optional(&self, name: &str, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
        let Some(mut file) = self.open_private_optional(name)? else {
            return Ok(None);
        };
        let metadata = file.metadata().map_err(|error| {
            BridgeFsError::io("read_failed", self.display_path.join(name).display(), error)
        })?;
        if metadata.len() > maximum as u64 {
            return Err(BridgeFsError::new(
                "message_too_large",
                format!(
                    "{} is {} bytes; maximum is {maximum}",
                    self.display_path.join(name).display(),
                    metadata.len()
                ),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes).map_err(|error| {
            BridgeFsError::io("read_failed", self.display_path.join(name).display(), error)
        })?;
        if bytes.len() > maximum {
            return Err(BridgeFsError::new(
                "message_too_large",
                format!(
                    "{} grew beyond {maximum} bytes",
                    self.display_path.join(name).display()
                ),
            ));
        }
        Ok(Some(bytes))
    }

    /// Read one request with a one-byte overflow sentinel.  This is the sole
    /// exception to exact bounded reads: Lua must be able to consume and emit
    /// a typed acknowledgement for an oversized but canonical request name.
    fn read_request_for_classification(
        &self,
        name: &str,
        maximum: usize,
    ) -> BridgeResult<ObservedRequest> {
        let Some(mut file) = self.open_private_optional(name)? else {
            return Err(BridgeFsError::new(
                "request_disappeared",
                format!("request {name:?} disappeared during enumeration"),
            ));
        };
        let before = file.metadata().map_err(|error| {
            BridgeFsError::io("read_failed", self.display_path.join(name).display(), error)
        })?;
        let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
        Read::by_ref(&mut file)
            .take(maximum.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                BridgeFsError::io("read_failed", self.display_path.join(name).display(), error)
            })?;
        let after = file.metadata().map_err(|error| {
            BridgeFsError::io("read_failed", self.display_path.join(name).display(), error)
        })?;
        if before.len() != after.len() {
            return Err(BridgeFsError::new(
                "request_changed",
                format!("request {name:?} changed length while being read"),
            ));
        }
        Ok(ObservedRequest {
            file,
            body: bytes,
            length: after.len(),
        })
    }

    fn create_temp(&self, name: &str, bytes: &[u8]) -> BridgeResult<File> {
        validate_component(name)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(BridgeFsError::new(
                "message_too_large",
                format!(
                    "document is {} bytes; maximum is {MAX_DOCUMENT_BYTES}",
                    bytes.len()
                ),
            ));
        }
        let c_name = CString::new(name).expect("validated component");
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(BridgeFsError::io(
                "write_failed",
                self.display_path.join(name).display(),
                io::Error::last_os_error(),
            ));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let operation = (|| -> io::Result<()> {
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(io::Error::last_os_error());
            }
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if let Err(error) = operation {
            let _ = self.unlink(name);
            return Err(BridgeFsError::io(
                "write_failed",
                self.display_path.join(name).display(),
                error,
            ));
        }
        validate_file(&file, &self.display_path.join(name))?;
        Ok(file)
    }

    fn write_new_atomic(&self, name: &str, bytes: &[u8]) -> BridgeResult<()> {
        validate_component(name)?;
        if let Some(existing) = self.open_private_optional(name)? {
            drop(existing);
            return Err(BridgeFsError::new(
                "already_exists",
                format!("{} already exists", self.display_path.join(name).display()),
            ));
        }
        let temporary = format!(".tmp-{}", Uuid::new_v4());
        let file = self.create_temp(&temporary, bytes)?;
        let temporary_c = CString::new(temporary.as_str()).expect("generated component");
        let name_c = CString::new(name).expect("validated component");
        let rc = unsafe {
            libc::linkat(
                self.file.as_raw_fd(),
                temporary_c.as_ptr(),
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                0,
            )
        };
        drop(file);
        let _ = self.unlink(&temporary);
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                // Validate an existing object before classifying it as a
                // benign conflict.  A symlink/FIFO is bridge corruption.
                self.open_private_optional(name)?;
                return Err(BridgeFsError::new(
                    "already_exists",
                    format!("{} already exists", self.display_path.join(name).display()),
                ));
            }
            return Err(BridgeFsError::io(
                "write_failed",
                self.display_path.join(name).display(),
                error,
            ));
        }
        self.open_private_optional(name)?.ok_or_else(|| {
            BridgeFsError::new("write_failed", format!("published {name:?} is absent"))
        })?;
        sync_directory(&self.file)
    }

    fn write_replace_atomic(&self, name: &str, bytes: &[u8]) -> BridgeResult<()> {
        validate_component(name)?;
        // A suspicious existing object is never silently replaced.
        if let Some(existing) = self.open_private_optional(name)? {
            drop(existing);
        }
        let temporary = format!(".tmp-{}", Uuid::new_v4());
        let file = self.create_temp(&temporary, bytes)?;
        let temporary_c = CString::new(temporary.as_str()).expect("generated component");
        let name_c = CString::new(name).expect("validated component");
        let rc = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                temporary_c.as_ptr(),
                self.file.as_raw_fd(),
                name_c.as_ptr(),
            )
        };
        drop(file);
        if rc != 0 {
            let error = io::Error::last_os_error();
            let _ = self.unlink(&temporary);
            return Err(BridgeFsError::io(
                "write_failed",
                self.display_path.join(name).display(),
                error,
            ));
        }
        self.open_private_optional(name)?.ok_or_else(|| {
            BridgeFsError::new("write_failed", format!("published {name:?} is absent"))
        })?;
        sync_directory(&self.file)
    }

    fn entry_names(&self) -> BridgeResult<Vec<OsString>> {
        let duplicate = unsafe { libc::dup(self.file.as_raw_fd()) };
        if duplicate < 0 {
            return Err(BridgeFsError::io(
                "enumerate_failed",
                self.display_path.display(),
                io::Error::last_os_error(),
            ));
        }
        let directory = unsafe { libc::fdopendir(duplicate) };
        if directory.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(duplicate) };
            return Err(BridgeFsError::io(
                "enumerate_failed",
                self.display_path.display(),
                error,
            ));
        }
        // `dup` shares the directory offset with the held descriptor.  The
        // consumer polls repeatedly, so reset the stream explicitly before
        // every enumeration rather than observing EOF forever after poll 1.
        unsafe { libc::rewinddir(directory) };
        let mut names = Vec::new();
        loop {
            set_errno(0);
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                let error_number = get_errno();
                unsafe { libc::closedir(directory) };
                if error_number != 0 {
                    return Err(BridgeFsError::io(
                        "enumerate_failed",
                        self.display_path.display(),
                        io::Error::from_raw_os_error(error_number),
                    ));
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes != b"." && bytes != b".." {
                names.push(OsString::from_vec(bytes.to_vec()));
            }
        }
        Ok(names)
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in component"))?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Descriptor-held instance spool.  Dropping the userdata releases both the
/// kernel lock and the same-process claim; all directory handles stay stable
/// across path replacement for the full consumer lifetime.
#[derive(Debug)]
pub(super) struct DmuxBridgeSpool {
    instance: String,
    pid: u32,
    process_start_token: String,
    key: Vec<u8>,
    _lease: File,
    _claim: ActiveLeaseClaim,
    requests: PrivateDir,
    acks: PrivateDir,
    consumed: PrivateDir,
    context: PrivateDir,
    instance_dir: PrivateDir,
    observed_requests: Mutex<BTreeMap<String, ObservedRequest>>,
}

#[derive(Debug)]
struct ObservedRequest {
    file: File,
    body: Vec<u8>,
    length: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionAck {
    protocol_version: u32,
    uid: String,
    action: String,
    nonce: String,
    ok: bool,
    completed_at: u64,
    request_sha256: String,
    gui_instance: String,
    platform_action: String,
    #[serde(default)]
    already_hidden: Option<bool>,
}

#[derive(Debug)]
struct BridgePreflight {
    key_bytes: usize,
    backend_instance_uid: String,
    server_epoch: String,
}

fn bridge_preflight() -> BridgeResult<BridgePreflight> {
    let base = platform_runtime_base()?;
    let key_bytes = bridge_key_preflight_at_base(&base)?;
    let raw = mux_lua::dmux_descriptor::read_verified_descriptor(MAX_DOCUMENT_BYTES)
        .map_err(|error| BridgeFsError::new("descriptor_unavailable", error.to_string()))?;
    let (backend_instance_uid, server_epoch) = verified_descriptor_identity(raw)?;
    Ok(BridgePreflight {
        key_bytes,
        backend_instance_uid,
        server_epoch,
    })
}

fn bridge_key_preflight_at_base(base: &Path) -> BridgeResult<usize> {
    let base = PrivateDir::open_platform_base(base)?;
    let runtime = base.child("dmux")?;
    let bridge = runtime.child(BRIDGE_DIR)?;
    let key = bridge
        .read_private_optional(KEY_FILE, 32)?
        .ok_or_else(|| BridgeFsError::new("key_unavailable", "bridge/key is absent"))?;
    if key.len() != 32 {
        return Err(BridgeFsError::new(
            "key_invalid",
            format!("bridge key contains {} bytes; expected 32", key.len()),
        ));
    }
    Ok(key.len())
}

impl DmuxBridgeSpool {
    fn open(instance: &str) -> BridgeResult<Self> {
        // Capture the immutable cold-launch parent witness before a config
        // reload or launcher exit can erase the initial parent relationship.
        captured_launcher_witness()?;
        let base = platform_runtime_base()?;
        Self::open_at_base(
            &base,
            instance,
            std::process::id(),
            &current_process_start_token()?,
        )
    }

    fn open_at_base(
        base: &Path,
        instance: &str,
        pid: u32,
        start_token: &str,
    ) -> BridgeResult<Self> {
        validate_instance(instance)?;
        if pid == 0 || start_token.is_empty() || start_token.len() > 256 {
            return Err(BridgeFsError::new(
                "identity_invalid",
                "GUI process identity is incomplete",
            ));
        }

        let base = PrivateDir::open_platform_base(base)?;
        let runtime = base.ensure_child("dmux")?;
        let bridge = runtime.ensure_child(BRIDGE_DIR)?;
        let key = bridge
            .read_private_optional(KEY_FILE, 32)?
            .ok_or_else(|| BridgeFsError::new("key_unavailable", "bridge/key is absent"))?;
        if key.len() != 32 {
            return Err(BridgeFsError::new(
                "key_invalid",
                format!("bridge key contains {} bytes; expected 32", key.len()),
            ));
        }
        let instances = bridge.ensure_child(INSTANCES_DIR)?;
        let instance_dir = instances.ensure_child(instance)?;
        let requests = instance_dir.ensure_child("requests")?;
        let acks = instance_dir.ensure_child("acks")?;
        let consumed = instance_dir.ensure_child("consumed")?;
        let context = instance_dir.ensure_child("context")?;

        let claim = ActiveLeaseClaim::claim(instance)?;
        let lease = acquire_instance_lease(&instance_dir, instance, pid, start_token)?;

        Ok(Self {
            instance: instance.to_string(),
            pid,
            process_start_token: start_token.to_string(),
            key,
            _lease: lease,
            _claim: claim,
            requests,
            acks,
            consumed,
            context,
            instance_dir,
            observed_requests: Mutex::new(BTreeMap::new()),
        })
    }

    fn validate_maximum(maximum: usize) -> BridgeResult<usize> {
        if maximum == 0 || maximum > MAX_DOCUMENT_BYTES {
            return Err(BridgeFsError::new(
                "invalid_limit",
                format!("document limit must be between 1 and {MAX_DOCUMENT_BYTES}"),
            ));
        }
        Ok(maximum)
    }

    fn next_request(&self, maximum: usize) -> BridgeResult<Option<(String, Vec<u8>)>> {
        self.require_lease()?;
        let maximum = Self::validate_maximum(maximum)?;
        let mut requests = Vec::new();
        for name in self.requests.entry_names()? {
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(uid) = request_uid_from_name(name) else {
                continue;
            };
            requests.push((name.to_string(), uid));
        }
        requests.sort_by(|left, right| left.0.cmp(&right.0));
        let Some((name, uid)) = requests.into_iter().next() else {
            return Ok(None);
        };
        let observed = self
            .requests
            .read_request_for_classification(&name, maximum)?;
        let body = observed.body.clone();
        self.observed_requests.lock().insert(uid.clone(), observed);
        Ok(Some((uid, body)))
    }

    fn read_consumed(&self, uid: &str, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
        self.require_lease()?;
        validate_uid(uid)?;
        self.consumed
            .read_private_optional(&format!("req-{uid}.json"), Self::validate_maximum(maximum)?)
    }

    fn consume_request_new(&self, uid: &str) -> BridgeResult<()> {
        self.require_lease()?;
        validate_uid(uid)?;
        let name = format!("req-{uid}.json");

        // Validate the source before attempting the no-replace transition.
        // We validate the destination after the atomic rename as well.
        let current_source = self.requests.open_private_optional(&name)?.ok_or_else(|| {
            BridgeFsError::new("request_disappeared", format!("{name} is absent"))
        })?;
        if let Some(existing) = self.consumed.open_private_optional(&name)? {
            drop(existing);
            return Err(BridgeFsError::new(
                "already_consumed",
                format!("consumed/{name} already exists; refusing to replace replay evidence"),
            ));
        }
        let mut observed = self.observed_requests.lock().remove(uid).ok_or_else(|| {
            BridgeFsError::new(
                "request_unobserved",
                "consume_request_new requires bytes returned by next_request on this handle",
            )
        })?;
        let observed_metadata = observed.file.metadata().map_err(|error| {
            BridgeFsError::io("request_changed", format!("requests/{name}"), error)
        })?;
        let current_metadata = current_source.metadata().map_err(|error| {
            BridgeFsError::io("request_changed", format!("requests/{name}"), error)
        })?;
        if observed_metadata.dev() != current_metadata.dev()
            || observed_metadata.ino() != current_metadata.ino()
            || observed.length != current_metadata.len()
        {
            return Err(BridgeFsError::new(
                "request_changed",
                "request inode changed after next_request",
            ));
        }
        drop(current_source);

        let old_name = CString::new(name.as_str()).expect("validated component");
        let new_name = CString::new(name.as_str()).expect("validated component");
        let rc = rename_noreplace(
            self.requests.file.as_raw_fd(),
            &old_name,
            self.consumed.file.as_raw_fd(),
            &new_name,
        );
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                // Do not collapse a corrupt/symlink destination into the
                // ordinary replay state.
                self.consumed.open_private_optional(&name)?;
                return Err(BridgeFsError::new(
                    "already_consumed",
                    format!("consumed/{name} already exists; refusing to replace replay evidence"),
                ));
            }
            return Err(BridgeFsError::io(
                "consume_failed",
                format!("requests/{name} -> consumed/{name}"),
                error,
            ));
        }

        let consumed_file = self
            .consumed
            .open_private_optional(&name)?
            .ok_or_else(|| BridgeFsError::new("consume_failed", "consumed request is absent"))?;
        let consumed_metadata = consumed_file.metadata().map_err(|error| {
            BridgeFsError::io("consume_failed", format!("consumed/{name}"), error)
        })?;
        if observed_metadata.dev() != consumed_metadata.dev()
            || observed_metadata.ino() != consumed_metadata.ino()
            || observed.length != consumed_metadata.len()
        {
            return Err(BridgeFsError::new(
                "request_changed",
                "atomic consume moved a different request inode",
            ));
        }
        drop(consumed_file);

        observed.file.seek(SeekFrom::Start(0)).map_err(|error| {
            BridgeFsError::io("request_changed", format!("consumed/{name}"), error)
        })?;
        let mut current_body = Vec::with_capacity(observed.body.len());
        Read::by_ref(&mut observed.file)
            .take(observed.body.len() as u64)
            .read_to_end(&mut current_body)
            .map_err(|error| {
                BridgeFsError::io("request_changed", format!("consumed/{name}"), error)
            })?;
        if current_body != observed.body {
            return Err(BridgeFsError::new(
                "request_changed",
                "request bytes changed after next_request",
            ));
        }
        sync_directory(&self.requests.file)?;
        sync_directory(&self.consumed.file)
    }

    /// Remove only the exact request bytes/inode previously returned by
    /// `next_request`.  The bridge uses this after a durable primary/replay
    /// acknowledgement already proves that the request UID was consumed;
    /// it can never select an arbitrary path or silently delete a swapped
    /// request.
    fn discard_observed_request(&self, uid: &str) -> BridgeResult<()> {
        self.require_lease()?;
        validate_uid(uid)?;
        let name = format!("req-{uid}.json");
        let current = self.requests.open_private_optional(&name)?.ok_or_else(|| {
            BridgeFsError::new("request_disappeared", format!("{name} is absent"))
        })?;
        let mut observed = self.observed_requests.lock().remove(uid).ok_or_else(|| {
            BridgeFsError::new(
                "request_unobserved",
                "discard_observed_request requires bytes returned by next_request",
            )
        })?;
        let observed_metadata = observed.file.metadata().map_err(|error| {
            BridgeFsError::io("request_changed", format!("requests/{name}"), error)
        })?;
        let current_metadata = current.metadata().map_err(|error| {
            BridgeFsError::io("request_changed", format!("requests/{name}"), error)
        })?;
        if observed_metadata.dev() != current_metadata.dev()
            || observed_metadata.ino() != current_metadata.ino()
            || observed.length != current_metadata.len()
        {
            return Err(BridgeFsError::new(
                "request_changed",
                "request inode changed after next_request",
            ));
        }
        drop(current);
        observed.file.seek(SeekFrom::Start(0)).map_err(|error| {
            BridgeFsError::io("request_changed", format!("requests/{name}"), error)
        })?;
        let mut current_body = Vec::with_capacity(observed.body.len());
        Read::by_ref(&mut observed.file)
            .take(observed.body.len() as u64)
            .read_to_end(&mut current_body)
            .map_err(|error| {
                BridgeFsError::io("request_changed", format!("requests/{name}"), error)
            })?;
        if current_body != observed.body {
            return Err(BridgeFsError::new(
                "request_changed",
                "request bytes changed after next_request",
            ));
        }
        self.requests.unlink(&name).map_err(|error| {
            BridgeFsError::io("discard_failed", format!("requests/{name}"), error)
        })?;
        let after = observed.file.metadata().map_err(|error| {
            BridgeFsError::io("discard_failed", format!("requests/{name}"), error)
        })?;
        if after.nlink() != 0 {
            return Err(BridgeFsError::new(
                "request_changed",
                "discard removed a different request inode",
            ));
        }
        sync_directory(&self.requests.file)
    }

    fn read_ack(&self, uid: &str, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
        self.require_lease()?;
        validate_uid(uid)?;
        self.acks
            .read_private_optional(&format!("ack-{uid}.json"), Self::validate_maximum(maximum)?)
    }

    fn write_ack_new(&self, uid: &str, body: &[u8]) -> BridgeResult<()> {
        self.require_lease()?;
        validate_uid(uid)?;
        self.acks.write_new_atomic(&format!("ack-{uid}.json"), body)
    }

    fn write_replay_ack_new(&self, uid: &str, body: &[u8]) -> BridgeResult<()> {
        self.require_lease()?;
        validate_uid(uid)?;
        self.acks
            .write_new_atomic(&format!("ack-{uid}.replay.json"), body)
    }

    fn consume_lifecycle_completion_proof(
        &self,
        uid: &str,
        platform_action: &str,
    ) -> BridgeResult<()> {
        self.require_lease()?;
        validate_uid(uid)?;
        if !matches!(platform_action, "quit" | "hide") {
            return Err(BridgeFsError::new(
                "completion_action",
                "platform_action must be quit or hide",
            ));
        }
        let consumed = self
            .read_consumed(uid, MAX_DOCUMENT_BYTES)?
            .ok_or_else(|| {
                BridgeFsError::new(
                    "completion_proof_missing",
                    "the exact consumed request is absent",
                )
            })?;
        let ack = self.read_ack(uid, MAX_DOCUMENT_BYTES)?.ok_or_else(|| {
            BridgeFsError::new(
                "completion_proof_missing",
                "the durable primary acknowledgement is absent",
            )
        })?;
        let digest = validate_lifecycle_completion_documents(
            &consumed,
            &ack,
            uid,
            &self.instance,
            self.pid,
            &self.process_start_token,
            platform_action,
            &self.key,
        )?;

        let process_key = format!("{}:{uid}", self.instance);
        if !COMPLETED_LIFECYCLE_PROOFS.lock().insert(process_key) {
            return Err(BridgeFsError::new(
                "completion_replayed",
                "this lifecycle proof was already consumed in this GUI process",
            ));
        }
        self.acks
            .write_new_atomic(
                &format!("completion-{uid}.json"),
                format!("{platform_action}:{digest}\n").as_bytes(),
            )
            .map_err(|error| {
                BridgeFsError::new(
                    "completion_replayed",
                    format!("durable lifecycle proof consumption failed: {error}"),
                )
            })
    }

    fn complete_safe_lifecycle(&self, uid: &str, platform_action: &str) -> BridgeResult<()> {
        match platform_action {
            "quit" => crate::dmux_managed::require_managed_safe_quit_api(
                config::configuration().dmux_managed_gui,
            ),
            "hide" => crate::dmux_managed::require_managed_safe_hide_api(
                config::configuration().dmux_managed_gui,
            ),
            _ => {
                return Err(BridgeFsError::new(
                    "completion_action",
                    "platform_action must be quit or hide",
                ))
            }
        }
        .map_err(|error| BridgeFsError::new("completion_disabled", error.to_string()))?;
        let connection = Connection::get().ok_or_else(|| {
            BridgeFsError::new(
                "completion_thread",
                "managed lifecycle completion is not running on the GUI thread",
            )
        })?;
        self.consume_lifecycle_completion_proof(uid, platform_action)?;
        match platform_action {
            "quit" => {
                log::info!("dmux descriptor-capability safe quit accepted for {uid}");
                connection.terminate_message_loop();
            }
            "hide" => {
                log::info!("dmux descriptor-capability safe hide accepted for {uid}");
                connection.hide_application();
            }
            _ => unreachable!("validated platform action"),
        }
        Ok(())
    }

    fn read_context(&self, pane_id: u64, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
        self.require_lease()?;
        if pane_id > 9_007_199_254_740_991 {
            return Err(BridgeFsError::new(
                "invalid_pane_id",
                "pane id exceeds the exact Lua integer range",
            ));
        }
        self.context
            .read_private_optional(&format!("{pane_id}.json"), Self::validate_maximum(maximum)?)
    }

    fn write_heartbeat(&self, body: &[u8]) -> BridgeResult<()> {
        // Re-read the lease identity before publishing each liveness witness.
        // A changed lease inode or body is corruption, not authority.
        validate_lease_identity(
            &self.instance_dir,
            &self._lease,
            &self.instance,
            self.pid,
            &self.process_start_token,
        )?;
        self.instance_dir
            .write_replace_atomic("heartbeat.json", body)
    }

    fn require_lease(&self) -> BridgeResult<()> {
        validate_lease_identity(
            &self.instance_dir,
            &self._lease,
            &self.instance,
            self.pid,
            &self.process_start_token,
        )
    }

    fn consume_launcher_witness(&self, origin: LauncherOrigin) -> BridgeResult<()> {
        self.require_lease()?;
        let captured = captured_launcher_witness()?.ok_or_else(|| {
            BridgeFsError::new(
                "launcher_witness_unavailable",
                "this GUI process was not launched with a complete broker witness",
            )
        })?;
        validate_launcher_witness(captured, &origin, &self.instance)?;
        let live_start = mux_lua::dmux_descriptor::process_start_token(captured.origin.pid)
            .map_err(|error| BridgeFsError::new("launcher_witness_stale", error.to_string()))?;
        if live_start != captured.origin.start_token {
            return Err(BridgeFsError::new(
                "launcher_witness_stale",
                "launcher pid no longer names the captured process incarnation",
            ));
        }
        let backend = verified_descriptor_backend_instance()?;
        if backend != captured.transport_backend_instance_uid {
            return Err(BridgeFsError::new(
                "launcher_witness_stale",
                "managed service backend identity changed before witness consumption",
            ));
        }
        if LAUNCHER_WITNESS_CONSUMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(BridgeFsError::new(
                "launcher_witness_replayed",
                "cold-launch broker witness was already consumed in this GUI process",
            ));
        }
        Ok(())
    }
}

impl UserData for DmuxBridgeSpool {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("key", |lua, this, _: ()| lua.create_string(&this.key));
        methods.add_method("identity", |lua, this, _: ()| {
            let identity = lua.create_table()?;
            identity.set("gui_instance", this.instance.as_str())?;
            identity.set("pid", this.pid)?;
            identity.set("process_start_token", this.process_start_token.as_str())?;
            Ok(identity)
        });
        methods.add_method("write_heartbeat_atomic", |_, this, body: LuaString| {
            this.write_heartbeat(body.as_bytes().as_ref())
                .map_err(luaerr)
        });
        methods.add_method("next_request", |lua, this, maximum: usize| {
            match this.next_request(maximum).map_err(luaerr)? {
                Some((uid, body)) => Ok((Some(uid), Some(lua.create_string(&body)?))),
                None => Ok((None, None)),
            }
        });
        methods.add_method(
            "read_consumed",
            |lua, this, (uid, maximum): (String, usize)| {
                optional_lua_bytes(lua, this.read_consumed(&uid, maximum).map_err(luaerr)?)
            },
        );
        methods.add_method("consume_request_new", |_, this, uid: String| {
            this.consume_request_new(&uid).map_err(luaerr)
        });
        methods.add_method("discard_observed_request", |_, this, uid: String| {
            this.discard_observed_request(&uid).map_err(luaerr)
        });
        methods.add_method("consume_launcher_witness", |_, this, origin: Table| {
            let origin = launcher_witness_from_lua(origin)?;
            this.consume_launcher_witness(origin).map_err(luaerr)
        });
        methods.add_method("resident_brokered", |_, this, _: ()| {
            this.require_lease().map_err(luaerr)?;
            Ok(LAUNCHER_WITNESS_CONSUMED.load(Ordering::Acquire))
        });
        methods.add_method("read_ack", |lua, this, (uid, maximum): (String, usize)| {
            optional_lua_bytes(lua, this.read_ack(&uid, maximum).map_err(luaerr)?)
        });
        methods.add_method(
            "write_ack_new",
            |_, this, (uid, body): (String, LuaString)| {
                this.write_ack_new(&uid, body.as_bytes().as_ref())
                    .map_err(luaerr)
            },
        );
        methods.add_method(
            "write_replay_ack_new",
            |_, this, (uid, body): (String, LuaString)| {
                this.write_replay_ack_new(&uid, body.as_bytes().as_ref())
                    .map_err(luaerr)
            },
        );
        methods.add_method(
            "complete_safe_lifecycle",
            |_, this, (uid, platform_action): (String, String)| {
                this.complete_safe_lifecycle(&uid, &platform_action)
                    .map_err(luaerr)
            },
        );
        methods.add_method(
            "read_context",
            |lua, this, (pane_id, maximum): (u64, usize)| {
                optional_lua_bytes(lua, this.read_context(pane_id, maximum).map_err(luaerr)?)
            },
        );
    }
}

fn optional_lua_bytes<'lua>(
    lua: &'lua Lua,
    value: Option<Vec<u8>>,
) -> mlua::Result<Option<LuaString<'lua>>> {
    value.map(|bytes| lua.create_string(&bytes)).transpose()
}

fn validate_lifecycle_completion_documents(
    request_raw: &[u8],
    ack_raw: &[u8],
    uid: &str,
    instance: &str,
    pid: u32,
    process_start_token: &str,
    platform_action: &str,
    key: &[u8],
) -> BridgeResult<String> {
    let request: serde_json::Value = serde_json::from_slice(request_raw).map_err(|error| {
        BridgeFsError::new(
            "completion_proof_invalid",
            format!("consumed request is not JSON: {error}"),
        )
    })?;
    if contains_json_null(&request) {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "consumed request contains a null field",
        ));
    }
    let object = request.as_object().ok_or_else(|| {
        BridgeFsError::new(
            "completion_proof_invalid",
            "consumed request is not one JSON object",
        )
    })?;
    const REQUEST_KEYS: &[&str] = &[
        "action",
        "expiry",
        "hmac_sha256",
        "issued_at",
        "nonce",
        "origin",
        "protocol_version",
        "replay_key",
        "target",
        "uid",
    ];
    if object.len() != REQUEST_KEYS.len()
        || object
            .keys()
            .any(|key| !REQUEST_KEYS.contains(&key.as_str()))
    {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "consumed request does not have the exact bridge-v1 top-level schema",
        ));
    }
    if object
        .get("protocol_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || object.get("uid").and_then(serde_json::Value::as_str) != Some(uid)
        || object.get("action").and_then(serde_json::Value::as_str) != Some("safe_quit")
    {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "consumed request is not the exact safe_quit request UID",
        ));
    }
    let nonce = object
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BridgeFsError::new("completion_proof_invalid", "request nonce is absent"))?;
    if !(32..=128).contains(&nonce.len()) || !is_lower_hex(nonce) {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "request nonce is not canonical lowercase hexadecimal",
        ));
    }
    let issued_at = exact_json_u64(object.get("issued_at"), "request issued_at")?;
    let expiry = exact_json_u64(object.get("expiry"), "request expiry")?;
    if expiry <= issued_at || expiry - issued_at > 10 {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "request TTL is outside bridge-v1 bounds",
        ));
    }
    let origin = object
        .get("origin")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            BridgeFsError::new("completion_proof_invalid", "request origin is absent")
        })?;
    if !matches!(
        origin.get("kind").and_then(serde_json::Value::as_str),
        Some("in_gui" | "resident_gui")
    ) || origin
        .get("gui_instance")
        .and_then(serde_json::Value::as_str)
        != Some(instance)
        || origin.get("pid").and_then(serde_json::Value::as_u64) != Some(u64::from(pid))
        || origin
            .get("process_start_token")
            .and_then(serde_json::Value::as_str)
            != Some(process_start_token)
    {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "request origin does not name this exact resident/in-GUI process incarnation",
        ));
    }
    let target = object
        .get("target")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            BridgeFsError::new("completion_proof_invalid", "request target is absent")
        })?;
    const FINISH_KEYS: &[&str] = &["phase", "platform_action", "proof_uid"];
    if target.len() != FINISH_KEYS.len()
        || target
            .keys()
            .any(|key| !FINISH_KEYS.contains(&key.as_str()))
        || target.get("phase").and_then(serde_json::Value::as_str) != Some("finish")
        || target
            .get("platform_action")
            .and_then(serde_json::Value::as_str)
            != Some(platform_action)
    {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "request is not an exact safe_quit finish target for this platform action",
        ));
    }
    validate_uid(
        target
            .get("proof_uid")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                BridgeFsError::new("completion_proof_invalid", "finish proof_uid is absent")
            })?,
    )?;

    let signature = object
        .get("hmac_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BridgeFsError::new("completion_proof_invalid", "request HMAC is absent"))?;
    if signature.len() != 64 || !is_lower_hex(signature) {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "request HMAC is not 64 lowercase hexadecimal characters",
        ));
    }
    let canonical = canonical_unsigned_request(&request)?;
    let expected_signature = hex_lower(&hmac_sha256(key, &canonical));
    if !constant_time_equal(signature.as_bytes(), expected_signature.as_bytes()) {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "consumed request HMAC does not authenticate under this bridge key",
        ));
    }
    let digest = hex_lower(&Sha256::digest(&canonical));

    let ack_value: serde_json::Value = serde_json::from_slice(ack_raw).map_err(|error| {
        BridgeFsError::new(
            "completion_proof_invalid",
            format!("primary acknowledgement is not JSON: {error}"),
        )
    })?;
    if contains_json_null(&ack_value) {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "primary acknowledgement contains a null field",
        ));
    }
    let ack: CompletionAck = serde_json::from_value(ack_value).map_err(|error| {
        BridgeFsError::new(
            "completion_proof_invalid",
            format!("primary acknowledgement is not exact finish schema: {error}"),
        )
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| BridgeFsError::new("clock_invalid", error.to_string()))?
        .as_secs();
    if ack.protocol_version != 1
        || ack.uid != uid
        || ack.action != "safe_quit"
        || ack.nonce != nonce
        || !ack.ok
        || ack.completed_at > MAX_JSON_INTEGER
        || ack.completed_at < issued_at
        || ack.completed_at > expiry
        || ack.completed_at > now.saturating_add(2)
        || now > expiry
        || ack.request_sha256.len() != 64
        || !is_lower_hex(&ack.request_sha256)
        || !constant_time_equal(ack.request_sha256.as_bytes(), digest.as_bytes())
        || ack.gui_instance != instance
        || ack.platform_action != platform_action
        || ack.already_hidden.is_some()
    {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            "primary acknowledgement does not exactly prove this safe lifecycle completion",
        ));
    }
    Ok(digest)
}

fn exact_json_u64(value: Option<&serde_json::Value>, label: &str) -> BridgeResult<u64> {
    let value = value.and_then(serde_json::Value::as_u64).ok_or_else(|| {
        BridgeFsError::new(
            "completion_proof_invalid",
            format!("{label} is not an unsigned integer"),
        )
    })?;
    if value > MAX_JSON_INTEGER {
        return Err(BridgeFsError::new(
            "completion_proof_invalid",
            format!("{label} exceeds the exact JSON integer range"),
        ));
    }
    Ok(value)
}

fn contains_json_null(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::Array(values) => values.iter().any(contains_json_null),
        serde_json::Value::Object(values) => values.values().any(contains_json_null),
        _ => false,
    }
}

fn canonical_unsigned_request(request: &serde_json::Value) -> BridgeResult<Vec<u8>> {
    let mut unsigned = request.clone();
    unsigned
        .as_object_mut()
        .expect("validated request object")
        .remove("hmac_sha256");
    let mut output = Vec::new();
    write_canonical_json(&unsigned, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> BridgeResult<()> {
    match value {
        serde_json::Value::Null => Err(BridgeFsError::new(
            "completion_proof_invalid",
            "canonical bridge JSON cannot contain null",
        )),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
            Ok(())
        }
        serde_json::Value::Number(value) => {
            let encoded = if let Some(value) = value.as_u64() {
                if value > MAX_JSON_INTEGER {
                    return Err(BridgeFsError::new(
                        "completion_proof_invalid",
                        "canonical JSON integer exceeds exact range",
                    ));
                }
                value.to_string()
            } else if let Some(value) = value.as_i64() {
                if value.unsigned_abs() > MAX_JSON_INTEGER {
                    return Err(BridgeFsError::new(
                        "completion_proof_invalid",
                        "canonical JSON integer exceeds exact range",
                    ));
                }
                value.to_string()
            } else {
                return Err(BridgeFsError::new(
                    "completion_proof_invalid",
                    "canonical bridge JSON accepts only integers",
                ));
            };
            output.extend_from_slice(encoded.as_bytes());
            Ok(())
        }
        serde_json::Value::String(value) => {
            output.extend_from_slice(
                serde_json::to_string(value)
                    .expect("JSON string serialization")
                    .as_bytes(),
            );
            Ok(())
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
            Ok(())
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("JSON object key serialization")
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
            Ok(())
        }
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let normalized = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut key_block = [0u8; BLOCK];
    key_block[..normalized.len()].copy_from_slice(&normalized);
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    let mut outer = Vec::with_capacity(BLOCK + 32);
    for byte in key_block {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    outer.extend_from_slice(&Sha256::digest(&inner));
    Sha256::digest(&outer).into()
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String");
    }
    output
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn captured_launcher_witness() -> BridgeResult<Option<&'static LauncherWitness>> {
    match CAPTURED_LAUNCHER_WITNESS.get_or_init(capture_launcher_witness_from_process) {
        CapturedLauncherWitness::Absent => Ok(None),
        CapturedLauncherWitness::Present(witness) => Ok(Some(witness)),
        CapturedLauncherWitness::Invalid(detail) => Err(BridgeFsError::new(
            "launcher_witness_invalid",
            detail.clone(),
        )),
    }
}

fn capture_launcher_witness_from_process() -> CapturedLauncherWitness {
    let required_names = [
        ENV_GUI_INSTANCE,
        ENV_LAUNCHER_REQUEST_UID,
        ENV_LAUNCHER_PID,
        ENV_LAUNCHER_START_TOKEN,
        ENV_BACKEND_INSTANCE,
        ENV_TARGET_DOMAIN,
        ENV_TARGET_BACKEND_INSTANCE,
        ENV_TARGET_SERVER_EPOCH,
        ENV_TARGET_HOST_UID,
    ];
    let values: Vec<Option<OsString>> = required_names.iter().map(std::env::var_os).collect();
    let present = values.iter().filter(|value| value.is_some()).count();
    let optional_space = std::env::var_os(ENV_TARGET_SPACE_UID);
    if present == 0 && optional_space.is_none() {
        return CapturedLauncherWitness::Absent;
    }
    if present != required_names.len() {
        return CapturedLauncherWitness::Invalid(
            "cold-launch environment is partial; all mandatory broker witness fields are required"
                .into(),
        );
    }
    let mut utf8 = Vec::with_capacity(required_names.len());
    for (name, value) in required_names.iter().zip(values) {
        let value = value.expect("counted present");
        let Some(value) = value.to_str() else {
            return CapturedLauncherWitness::Invalid(format!("{name} is not valid UTF-8"));
        };
        utf8.push(value.to_string());
    }
    let optional_space = match optional_space {
        Some(value) => match value.to_str() {
            Some(value) => Some(value.to_string()),
            None => {
                return CapturedLauncherWitness::Invalid(format!(
                    "{ENV_TARGET_SPACE_UID} is not valid UTF-8"
                ))
            }
        },
        None => None,
    };
    let pid = match utf8[2].parse::<u32>() {
        Ok(pid) if pid > 0 && pid.to_string() == utf8[2] => pid,
        _ => {
            return CapturedLauncherWitness::Invalid(
                "DMUX_GUI_LAUNCHER_PID is not a canonical positive decimal pid".into(),
            );
        }
    };
    let parent = unsafe { libc::getppid() };
    if parent <= 0 || parent as u32 != pid {
        return CapturedLauncherWitness::Invalid(format!(
            "initial GUI parent pid {parent} does not match launcher pid {pid}"
        ));
    }
    let launcher_request_uid = &utf8[1];
    if let Err(error) = validate_uid(launcher_request_uid) {
        return CapturedLauncherWitness::Invalid(format!(
            "invalid launcher request uid: {}",
            error.detail
        ));
    }
    let expected_instance = format!("gui-{}", launcher_request_uid.replace('-', ""));
    if utf8[0] != expected_instance {
        return CapturedLauncherWitness::Invalid(
            "DMUX_GUI_INSTANCE is not deterministically bound to launcher request uid".into(),
        );
    }
    if let Err(error) = validate_uid(&utf8[4]) {
        return CapturedLauncherWitness::Invalid(format!(
            "invalid backend instance uid: {}",
            error.detail
        ));
    }
    if utf8[5].is_empty()
        || utf8[5].len() > 256
        || utf8[5].bytes().any(|byte| byte < b' ' || byte == 0x7f)
    {
        return CapturedLauncherWitness::Invalid(
            "DMUX_GUI_TARGET_DOMAIN is empty, oversized, or contains controls".into(),
        );
    }
    for (name, value) in [
        (ENV_TARGET_BACKEND_INSTANCE, &utf8[6]),
        (ENV_TARGET_SERVER_EPOCH, &utf8[7]),
        (ENV_TARGET_HOST_UID, &utf8[8]),
    ] {
        if let Err(error) = validate_uid(value) {
            return CapturedLauncherWitness::Invalid(format!("invalid {name}: {}", error.detail));
        }
    }
    if let Some(space_uid) = &optional_space {
        if let Err(error) = validate_uid(space_uid) {
            return CapturedLauncherWitness::Invalid(format!(
                "invalid {ENV_TARGET_SPACE_UID}: {}",
                error.detail
            ));
        }
    }
    let live_start = match mux_lua::dmux_descriptor::process_start_token(pid) {
        Ok(token) => token,
        Err(error) => {
            return CapturedLauncherWitness::Invalid(format!(
                "cannot verify launcher process: {error}"
            ));
        }
    };
    if utf8[3] != live_start {
        return CapturedLauncherWitness::Invalid(
            "launcher start token does not match its live OS process incarnation".into(),
        );
    }
    let backend = match verified_descriptor_backend_instance() {
        Ok(backend) => backend,
        Err(error) => {
            return CapturedLauncherWitness::Invalid(format!(
                "cannot bind launcher to verified managed service: {error}"
            ));
        }
    };
    if utf8[4] != backend {
        return CapturedLauncherWitness::Invalid(
            "launcher backend instance does not match verified managed descriptor".into(),
        );
    }
    CapturedLauncherWitness::Present(LauncherWitness {
        origin: LauncherOrigin {
            gui_instance: utf8[0].clone(),
            uid: unsafe { libc::geteuid() } as u64,
            pid,
            start_token: utf8[3].clone(),
            launcher_request_uid: launcher_request_uid.clone(),
            domain: utf8[5].clone(),
            backend_instance_uid: utf8[6].clone(),
            server_epoch: utf8[7].clone(),
            host_uid: utf8[8].clone(),
            space_uid: optional_space,
        },
        transport_backend_instance_uid: utf8[4].clone(),
    })
}

fn launcher_witness_from_lua(origin: Table) -> mlua::Result<LauncherOrigin> {
    const FIELDS: &[&str] = &[
        "gui_instance",
        "uid",
        "pid",
        "start_token",
        "launcher_request_uid",
        "domain",
        "backend_instance_uid",
        "server_epoch",
        "host_uid",
        "space_uid",
    ];
    for pair in origin.clone().pairs::<mlua::Value, mlua::Value>() {
        let (key, _) = pair?;
        let key = match key {
            mlua::Value::String(value) => value.to_str()?.to_string(),
            other => {
                return Err(mlua::Error::external(format!(
                    "dmux_bridge_launcher_witness_invalid: origin key is {} rather than a string",
                    other.type_name()
                )));
            }
        };
        if !FIELDS.contains(&key.as_str()) {
            return Err(mlua::Error::external(format!(
                "dmux_bridge_launcher_witness_invalid: unknown origin field {key:?}"
            )));
        }
    }
    Ok(LauncherOrigin {
        gui_instance: origin.raw_get("gui_instance")?,
        uid: origin.raw_get("uid")?,
        pid: origin.raw_get("pid")?,
        start_token: origin.raw_get("start_token")?,
        launcher_request_uid: origin.raw_get("launcher_request_uid")?,
        domain: origin.raw_get("domain")?,
        backend_instance_uid: origin.raw_get("backend_instance_uid")?,
        server_epoch: origin.raw_get("server_epoch")?,
        host_uid: origin.raw_get("host_uid")?,
        space_uid: origin.raw_get("space_uid")?,
    })
}

fn validate_launcher_witness(
    captured: &LauncherWitness,
    origin: &LauncherOrigin,
    leased_instance: &str,
) -> BridgeResult<()> {
    validate_instance(&origin.gui_instance)?;
    validate_uid(&origin.launcher_request_uid)?;
    validate_uid(&origin.backend_instance_uid)?;
    validate_uid(&origin.server_epoch)?;
    validate_uid(&origin.host_uid)?;
    if let Some(space_uid) = &origin.space_uid {
        validate_uid(space_uid)?;
    }
    if origin.domain.is_empty()
        || origin.domain.len() > 256
        || origin
            .domain
            .bytes()
            .any(|byte| byte < b' ' || byte == 0x7f)
        || origin.uid != unsafe { libc::geteuid() } as u64
        || origin.pid == 0
        || origin.start_token.is_empty()
        || origin.start_token.len() > 256
    {
        return Err(BridgeFsError::new(
            "launcher_witness_invalid",
            "cold-launch origin has invalid fixed domain or process identity",
        ));
    }
    if origin.gui_instance != leased_instance || origin != &captured.origin {
        return Err(BridgeFsError::new(
            "launcher_witness_mismatch",
            "cold-launch origin does not exactly match the captured broker witness",
        ));
    }
    Ok(())
}

fn verified_descriptor_backend_instance() -> BridgeResult<String> {
    let raw = mux_lua::dmux_descriptor::read_verified_descriptor(MAX_DOCUMENT_BYTES)
        .map_err(|error| BridgeFsError::new("descriptor_unavailable", error.to_string()))?;
    verified_descriptor_identity(raw).map(|(backend, _epoch)| backend)
}

fn verified_descriptor_identity(raw: Option<Vec<u8>>) -> BridgeResult<(String, String)> {
    let raw = raw.ok_or_else(|| {
        BridgeFsError::new(
            "descriptor_unavailable",
            "managed service descriptor is absent",
        )
    })?;
    let descriptor: serde_json::Value = serde_json::from_slice(&raw).map_err(|error| {
        BridgeFsError::new(
            "descriptor_unavailable",
            format!("descriptor JSON: {error}"),
        )
    })?;
    let backend = descriptor
        .get("backend_instance_uid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BridgeFsError::new(
                "descriptor_unavailable",
                "verified descriptor omitted backend_instance_uid",
            )
        })?;
    validate_uid(backend)?;
    let epoch = descriptor
        .get("epoch")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BridgeFsError::new(
                "descriptor_unavailable",
                "verified descriptor omitted epoch",
            )
        })?;
    validate_uid(epoch)?;
    Ok((backend.to_string(), epoch.to_string()))
}

pub(super) fn register(lua: &Lua, gui: &Table) -> anyhow::Result<()> {
    gui.set(
        "dmux_bridge_capabilities",
        lua.create_function(|lua, _: ()| {
            let capabilities = lua.create_table()?;
            capabilities.set("version", API_VERSION)?;
            capabilities.set("descriptor_backed_spool", true)?;
            capabilities.set("exclusive_instance_lease", true)?;
            capabilities.set("zero_window_lifecycle", true)?;
            capabilities.set("capability_bound_lifecycle_completion", true)?;
            capabilities.set("verified_mux_descriptor", true)?;
            capabilities.set("checked_preflight", true)?;
            capabilities.set("launcher_witness", true)?;
            capabilities.set("max_document_bytes", MAX_DOCUMENT_BYTES)?;
            Ok(capabilities)
        })?,
    )?;
    gui.set(
        "dmux_bridge_preflight",
        lua.create_function(|lua, _: ()| {
            // This check intentionally has no managed-config gate: it runs
            // while the new configuration is still being evaluated.  It is
            // read-only and acquires neither an instance directory nor lease.
            let preflight = bridge_preflight().map_err(luaerr)?;
            let witness = captured_launcher_witness().map_err(luaerr)?;
            let result = lua.create_table()?;
            result.set("version", API_VERSION)?;
            result.set("key_bytes", preflight.key_bytes)?;
            result.set("runtime_verified", true)?;
            result.set("verified_mux_descriptor", true)?;
            result.set("backend_instance_uid", preflight.backend_instance_uid)?;
            result.set("server_epoch", preflight.server_epoch)?;
            result.set("launcher_witness_present", witness.is_some())?;
            Ok(result)
        })?,
    )?;
    gui.set(
        "dmux_bridge_open",
        lua.create_function(|_, instance: String| {
            crate::dmux_managed::require_managed_safe_quit_api(
                config::configuration().dmux_managed_gui,
            )
            .map_err(mlua::Error::external)?;
            DmuxBridgeSpool::open(&instance).map_err(luaerr)
        })?,
    )?;
    gui.set(
        "dmux_read_mux_descriptor",
        lua.create_function(|lua, maximum: usize| {
            let bytes = mux_lua::dmux_descriptor::read_verified_descriptor(maximum)
                .map_err(mlua::Error::external)?;
            optional_lua_bytes(lua, bytes)
        })?,
    )?;
    Ok(())
}

fn acquire_instance_lease(
    instance_dir: &PrivateDir,
    instance: &str,
    pid: u32,
    start_token: &str,
) -> BridgeResult<File> {
    let name = CString::new(LEASE_FILE).expect("static component");
    let exclusive_fd = unsafe {
        libc::openat(
            instance_dir.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    let (fd, created) = if exclusive_fd >= 0 {
        (exclusive_fd, true)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(BridgeFsError::io(
                "lease_unavailable",
                instance_dir.display_path.join(LEASE_FILE).display(),
                error,
            ));
        }
        let existing_fd = unsafe {
            libc::openat(
                instance_dir.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        (existing_fd, false)
    };
    if fd < 0 {
        return Err(BridgeFsError::io(
            "lease_unavailable",
            instance_dir.display_path.join(LEASE_FILE).display(),
            io::Error::last_os_error(),
        ));
    }
    let mut lease = unsafe { File::from_raw_fd(fd) };
    if created && unsafe { libc::fchmod(lease.as_raw_fd(), 0o600) } != 0 {
        return Err(BridgeFsError::io(
            "lease_unavailable",
            instance_dir.display_path.join(LEASE_FILE).display(),
            io::Error::last_os_error(),
        ));
    }
    validate_file(&lease, &instance_dir.display_path.join(LEASE_FILE))?;
    if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        return Err(BridgeFsError::io(
            "duplicate_instance",
            format!("GUI instance {instance:?} is leased by another process"),
            error,
        ));
    }

    let body = serde_json::to_vec(&serde_json::json!({
        "lease_version": API_VERSION,
        "gui_instance": instance,
        "pid": pid,
        "process_start_token": start_token,
    }))
    .map_err(|error| BridgeFsError::new("lease_invalid", error.to_string()))?;
    lease
        .set_len(0)
        .and_then(|_| lease.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|_| lease.write_all(&body))
        .and_then(|_| lease.sync_all())
        .map_err(|error| {
            BridgeFsError::io(
                "lease_unavailable",
                instance_dir.display_path.join(LEASE_FILE).display(),
                error,
            )
        })?;
    sync_directory(&instance_dir.file)?;
    Ok(lease)
}

fn validate_lease_identity(
    instance_dir: &PrivateDir,
    held: &File,
    instance: &str,
    pid: u32,
    start_token: &str,
) -> BridgeResult<()> {
    validate_file(held, &instance_dir.display_path.join(LEASE_FILE)).map_err(|error| {
        BridgeFsError::new(
            "lease_lost",
            format!("held consumer lease: {}", error.detail),
        )
    })?;
    let current = instance_dir
        .open_private_optional(LEASE_FILE)?
        .ok_or_else(|| BridgeFsError::new("lease_lost", "consumer lease path is absent"))?;
    let held_metadata = held
        .metadata()
        .map_err(|error| BridgeFsError::io("lease_lost", "held consumer lease", error))?;
    let current_metadata = current
        .metadata()
        .map_err(|error| BridgeFsError::io("lease_lost", "current consumer lease", error))?;
    if held_metadata.dev() != current_metadata.dev()
        || held_metadata.ino() != current_metadata.ino()
    {
        return Err(BridgeFsError::new(
            "lease_lost",
            "consumer lease path no longer names the held lease inode",
        ));
    }
    drop(current);

    let raw = instance_dir
        .read_private_optional(LEASE_FILE, 1024)?
        .ok_or_else(|| BridgeFsError::new("lease_lost", "consumer lease is absent"))?;
    let expected = serde_json::json!({
        "lease_version": API_VERSION,
        "gui_instance": instance,
        "pid": pid,
        "process_start_token": start_token,
    });
    let actual: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|error| BridgeFsError::new("lease_lost", format!("lease JSON: {error}")))?;
    if actual != expected {
        return Err(BridgeFsError::new(
            "lease_lost",
            "consumer lease identity changed",
        ));
    }
    Ok(())
}

fn validate_dir(file: &File, path: &Path, exact_mode: Option<u32>) -> BridgeResult<()> {
    let metadata = file
        .metadata()
        .map_err(|error| BridgeFsError::io("unsafe_directory", path.display(), error))?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(BridgeFsError::new(
            "unsafe_directory",
            format!("{} is not a current-user-owned directory", path.display()),
        ));
    }
    let mode = metadata.mode() & 0o777;
    if let Some(exact) = exact_mode {
        if mode != exact {
            return Err(BridgeFsError::new(
                "unsafe_directory",
                format!(
                    "{} must be mode {exact:04o}, found {mode:04o}",
                    path.display()
                ),
            ));
        }
    } else if mode & 0o022 != 0 {
        return Err(BridgeFsError::new(
            "unsafe_directory",
            format!("{} is group- or world-writable", path.display()),
        ));
    }
    Ok(())
}

fn validate_file(file: &File, path: &Path) -> BridgeResult<()> {
    let metadata = file
        .metadata()
        .map_err(|error| BridgeFsError::io("unsafe_file", path.display(), error))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(BridgeFsError::new(
            "unsafe_file",
            format!(
                "{} must be a singly-linked current-user-owned mode-0600 regular file",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validate_component(component: &str) -> BridgeResult<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > 255
        || component.bytes().any(|byte| byte == b'/' || byte == 0)
    {
        return Err(BridgeFsError::new(
            "invalid_component",
            "unsafe bridge path component",
        ));
    }
    Ok(())
}

fn validate_instance(instance: &str) -> BridgeResult<()> {
    let bytes = instance.as_bytes();
    if bytes.len() < 2
        || bytes.len() > MAX_INSTANCE_BYTES
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(BridgeFsError::new(
            "invalid_instance",
            "GUI instance must be 2-160 safe ASCII characters",
        ));
    }
    Ok(())
}

fn validate_uid(uid: &str) -> BridgeResult<()> {
    let parsed = uid
        .parse::<Uuid>()
        .map_err(|_| BridgeFsError::new("invalid_uid", "request uid is not a UUID"))?;
    if parsed.to_string() != uid {
        return Err(BridgeFsError::new(
            "invalid_uid",
            "request uid must use canonical lowercase UUID spelling",
        ));
    }
    Ok(())
}

fn request_uid_from_name(name: &str) -> Option<String> {
    let uid = name.strip_prefix("req-")?.strip_suffix(".json")?;
    validate_uid(uid).ok()?;
    Some(uid.to_string())
}

fn sync_directory(file: &File) -> BridgeResult<()> {
    if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(BridgeFsError::io(
            "sync_failed",
            "bridge directory",
            io::Error::last_os_error(),
        ))
    }
}

fn current_process_start_token() -> BridgeResult<String> {
    let pid = std::process::id();
    let output = Command::new("/bin/ps")
        .env_clear()
        .env("LC_ALL", "C")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| BridgeFsError::io("identity_unavailable", "/bin/ps", error))?;
    if !output.status.success() {
        return Err(BridgeFsError::new(
            "identity_unavailable",
            format!("/bin/ps could not identify GUI pid {pid}"),
        ));
    }
    let token = std::str::from_utf8(&output.stdout)
        .context("/bin/ps start token is not UTF-8")
        .map_err(|error| BridgeFsError::new("identity_unavailable", error.to_string()))?
        .trim()
        .to_string();
    if token.is_empty() || token.len() > 256 {
        return Err(BridgeFsError::new(
            "identity_unavailable",
            "GUI process start token is empty or oversized",
        ));
    }
    Ok(token)
}

#[cfg(target_os = "linux")]
fn platform_runtime_base() -> BridgeResult<PathBuf> {
    let path = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| BridgeFsError::new("runtime_unavailable", "XDG_RUNTIME_DIR is not set"))?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(BridgeFsError::new(
            "runtime_unavailable",
            "XDG_RUNTIME_DIR must be absolute",
        ));
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn platform_runtime_base() -> BridgeResult<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

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
            return Err(BridgeFsError::io(
                "runtime_unavailable",
                "confstr(_CS_DARWIN_USER_TEMP_DIR)",
                io::Error::last_os_error(),
            ));
        }
        if required <= bytes.len() {
            bytes.truncate(required.saturating_sub(1));
            let path = PathBuf::from(OsString::from_vec(bytes));
            if !path.is_absolute() {
                return Err(BridgeFsError::new(
                    "runtime_unavailable",
                    "_CS_DARWIN_USER_TEMP_DIR is not absolute",
                ));
            }
            return Ok(path);
        }
        bytes.resize(required, 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_runtime_base() -> BridgeResult<PathBuf> {
    Err(BridgeFsError::new(
        "runtime_unavailable",
        "the dmux bridge supports only Linux and macOS",
    ))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(
    old_dir: libc::c_int,
    old_name: &CStr,
    new_dir: libc::c_int,
    new_name: &CStr,
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
    old_name: &CStr,
    new_dir: libc::c_int,
    new_name: &CStr,
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(
    old_dir: libc::c_int,
    old_name: &CStr,
    new_dir: libc::c_int,
    new_name: &CStr,
) -> libc::c_int {
    // Other Unix targets are not part of the managed dmux deployment.  Keep
    // compilation possible while retaining no-replace semantics.
    let linked = unsafe { libc::linkat(old_dir, old_name.as_ptr(), new_dir, new_name.as_ptr(), 0) };
    if linked != 0 {
        return linked;
    }
    unsafe { libc::unlinkat(old_dir, old_name.as_ptr(), 0) }
}

#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd"
)))]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

fn set_errno(value: libc::c_int) {
    unsafe { *errno_ptr() = value };
}

fn get_errno() -> libc::c_int {
    unsafe { *errno_ptr() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn base() -> tempfile::TempDir {
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateDir::open_platform_base(base.path()).unwrap();
        let runtime = root.ensure_child("dmux").unwrap();
        let bridge = runtime.ensure_child(BRIDGE_DIR).unwrap();
        bridge.write_new_atomic(KEY_FILE, &[7; 32]).unwrap();
        base
    }

    fn publish_request(spool: &DmuxBridgeSpool, uid: &str, body: &[u8]) {
        spool
            .requests
            .write_new_atomic(&format!("req-{uid}.json"), body)
            .unwrap();
    }

    fn signed_finish_documents(
        spool: &DmuxBridgeSpool,
        uid: &str,
        issued_at: u64,
        expiry: u64,
        completed_at: u64,
        origin_pid: u32,
        origin_start: &str,
        platform_action: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut request = serde_json::json!({
            "protocol_version": 1,
            "uid": uid,
            "action": "safe_quit",
            "target": {
                "phase": "finish",
                "proof_uid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "platform_action": platform_action,
            },
            "issued_at": issued_at,
            "expiry": expiry,
            "nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "replay_key": "cccccccccccccccccccccccccccccccc",
            "origin": {
                "kind": "resident_gui",
                "gui_instance": spool.instance,
                "pid": origin_pid,
                "process_start_token": origin_start,
            },
            "hmac_sha256": "",
        });
        let canonical = canonical_unsigned_request(&request).unwrap();
        request["hmac_sha256"] =
            serde_json::Value::String(hex_lower(&hmac_sha256(&spool.key, &canonical)));
        let digest = hex_lower(&Sha256::digest(&canonical));
        let ack = serde_json::json!({
            "protocol_version": 1,
            "uid": uid,
            "action": "safe_quit",
            "nonce": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ok": true,
            "completed_at": completed_at,
            "request_sha256": digest,
            "gui_instance": spool.instance,
            "platform_action": platform_action,
        });
        (
            serde_json::to_vec(&request).unwrap(),
            serde_json::to_vec(&ack).unwrap(),
        )
    }

    #[test]
    fn checked_preflight_is_read_only_and_validates_private_key() {
        let base = base();
        assert_eq!(bridge_key_preflight_at_base(base.path()).unwrap(), 32);

        let absent = tempfile::tempdir().unwrap();
        fs::set_permissions(absent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(bridge_key_preflight_at_base(absent.path()).is_err());
        assert!(!absent.path().join("dmux").exists());

        let root = PrivateDir::open_platform_base(base.path()).unwrap();
        let bridge = root.child("dmux").unwrap().child(BRIDGE_DIR).unwrap();
        bridge.unlink(KEY_FILE).unwrap();
        bridge.write_new_atomic(KEY_FILE, &[7; 31]).unwrap();
        assert_eq!(
            bridge_key_preflight_at_base(base.path()).unwrap_err().code,
            "key_invalid"
        );

        assert_eq!(
            verified_descriptor_identity(None).unwrap_err().code,
            "descriptor_unavailable"
        );
        assert_eq!(
            verified_descriptor_identity(Some(b"not-json".to_vec()))
                .unwrap_err()
                .code,
            "descriptor_unavailable"
        );
        let identity = verified_descriptor_identity(Some(
            br#"{"backend_instance_uid":"99999999-9999-4999-8999-999999999999","epoch":"88888888-8888-4888-8888-888888888888"}"#
                .to_vec(),
        ))
        .unwrap();
        assert_eq!(identity.0, "99999999-9999-4999-8999-999999999999");
        assert_eq!(identity.1, "88888888-8888-4888-8888-888888888888");
    }

    #[test]
    fn launcher_witness_is_exact_and_bound_to_leased_instance() {
        let witness = LauncherWitness {
            origin: LauncherOrigin {
                gui_instance: "gui-88888888888848888888888888888888".to_string(),
                uid: unsafe { libc::geteuid() } as u64,
                pid: 42,
                start_token: "macos:1:2".to_string(),
                launcher_request_uid: "88888888-8888-4888-8888-888888888888".to_string(),
                domain: "ssh:remote".to_string(),
                backend_instance_uid: "99999999-9999-4999-8999-999999999999".to_string(),
                server_epoch: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
                host_uid: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_string(),
                space_uid: Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string()),
            },
            transport_backend_instance_uid: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string(),
        };
        validate_launcher_witness(&witness, &witness.origin, &witness.origin.gui_instance).unwrap();

        let mut hostile = witness.origin.clone();
        hostile.launcher_request_uid = "77777777-7777-4777-8777-777777777777".to_string();
        assert_eq!(
            validate_launcher_witness(&witness, &hostile, &witness.origin.gui_instance)
                .unwrap_err()
                .code,
            "launcher_witness_mismatch"
        );
        assert_eq!(
            validate_launcher_witness(&witness, &witness.origin, "gui-different")
                .unwrap_err()
                .code,
            "launcher_witness_mismatch"
        );
    }

    #[test]
    fn rejects_untrusted_runtime_and_instance_components() {
        let writable = tempfile::tempdir().unwrap();
        fs::set_permissions(writable.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let error =
            DmuxBridgeSpool::open_at_base(writable.path(), "gui-ok", 1, "token").unwrap_err();
        assert_eq!(error.code, "unsafe_directory");

        let holder = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let link = holder.path().join("runtime-link");
        symlink(target.path(), &link).unwrap();
        let error = DmuxBridgeSpool::open_at_base(&link, "gui-ok", 1, "token").unwrap_err();
        assert!(matches!(
            error.code,
            "runtime_unavailable" | "unsafe_directory"
        ));

        let base = base();
        let error =
            DmuxBridgeSpool::open_at_base(base.path(), "../escape", 1, "token").unwrap_err();
        assert_eq!(error.code, "invalid_instance");
    }

    #[test]
    fn exclusive_lease_binds_instance_pid_and_start_token() {
        let base = base();
        let first = DmuxBridgeSpool::open_at_base(base.path(), "gui-lease", 41, "start-a").unwrap();
        let duplicate =
            DmuxBridgeSpool::open_at_base(base.path(), "gui-lease", 42, "start-b").unwrap_err();
        assert_eq!(duplicate.code, "duplicate_instance");

        let raw = first
            .instance_dir
            .read_private_optional(LEASE_FILE, 1024)
            .unwrap()
            .unwrap();
        let lease: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(lease["gui_instance"], "gui-lease");
        assert_eq!(lease["pid"], 41);
        assert_eq!(lease["process_start_token"], "start-a");

        drop(first);
        let second =
            DmuxBridgeSpool::open_at_base(base.path(), "gui-lease", 42, "start-b").unwrap();
        let lease_path = second.instance_dir.display_path.join(LEASE_FILE);
        drop(second);
        fs::set_permissions(&lease_path, fs::Permissions::from_mode(0o644)).unwrap();
        let unsafe_lease =
            DmuxBridgeSpool::open_at_base(base.path(), "gui-lease", 43, "start-c").unwrap_err();
        assert_eq!(unsafe_lease.code, "unsafe_file");
        assert_eq!(fs::metadata(lease_path).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn descriptor_spool_is_private_atomic_and_no_replace() {
        let base = base();
        let spool = DmuxBridgeSpool::open_at_base(base.path(), "gui-spool", 55, "start").unwrap();
        let uid = "01234567-89ab-4def-8123-456789abcdef";
        publish_request(&spool, uid, br#"{"protocol_version":1}"#);

        let (found_uid, body) = spool.next_request(MAX_DOCUMENT_BYTES).unwrap().unwrap();
        assert_eq!(found_uid, uid);
        assert_eq!(body, br#"{"protocol_version":1}"#);
        spool.consume_request_new(uid).unwrap();
        assert!(spool.next_request(MAX_DOCUMENT_BYTES).unwrap().is_none());
        assert_eq!(
            spool
                .read_consumed(uid, MAX_DOCUMENT_BYTES)
                .unwrap()
                .unwrap(),
            body
        );

        spool.write_ack_new(uid, b"ack-one").unwrap();
        assert_eq!(spool.read_ack(uid, 64).unwrap().unwrap(), b"ack-one");
        let duplicate = spool.write_ack_new(uid, b"ack-two").unwrap_err();
        assert_eq!(duplicate.code, "already_exists");
        assert_eq!(spool.read_ack(uid, 64).unwrap().unwrap(), b"ack-one");
        spool.write_replay_ack_new(uid, b"replay-one").unwrap();
        let duplicate = spool.write_replay_ack_new(uid, b"replay-two").unwrap_err();
        assert_eq!(duplicate.code, "already_exists");

        spool.write_heartbeat(b"heartbeat-one").unwrap();
        spool.write_heartbeat(b"heartbeat-two").unwrap();
        assert_eq!(
            spool
                .instance_dir
                .read_private_optional("heartbeat.json", 64)
                .unwrap()
                .unwrap(),
            b"heartbeat-two"
        );
        for (directory, name) in [
            (&spool.consumed, format!("req-{uid}.json")),
            (&spool.acks, format!("ack-{uid}.json")),
            (&spool.instance_dir, "heartbeat.json".to_string()),
        ] {
            let file = directory.open_private_optional(&name).unwrap().unwrap();
            assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn lifecycle_completion_requires_exact_consumed_ack_and_is_one_use() {
        let base = base();
        let spool =
            DmuxBridgeSpool::open_at_base(base.path(), "gui-completion", 61, "start-61").unwrap();
        let uid = "41234567-89ab-4def-8123-456789abcdef";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (request, ack) =
            signed_finish_documents(&spool, uid, now, now + 10, now, 61, "start-61", "quit");
        publish_request(&spool, uid, &request);
        let (observed_uid, _) = spool.next_request(MAX_DOCUMENT_BYTES).unwrap().unwrap();
        assert_eq!(observed_uid, uid);
        spool.consume_request_new(uid).unwrap();
        spool.write_ack_new(uid, &ack).unwrap();

        spool
            .consume_lifecycle_completion_proof(uid, "quit")
            .unwrap();
        assert!(spool
            .acks
            .read_private_optional(&format!("completion-{uid}.json"), 1024)
            .unwrap()
            .is_some());
        assert_eq!(
            spool
                .consume_lifecycle_completion_proof(uid, "quit")
                .unwrap_err()
                .code,
            "completion_replayed"
        );
    }

    #[test]
    fn lifecycle_completion_rejects_stale_incarnation_and_expired_proof() {
        let base = base();
        let spool =
            DmuxBridgeSpool::open_at_base(base.path(), "gui-completion-stale", 62, "start-62")
                .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stale_uid = "51234567-89ab-4def-8123-456789abcdef";
        let (request, ack) = signed_finish_documents(
            &spool,
            stale_uid,
            now,
            now + 10,
            now,
            999,
            "different-start",
            "quit",
        );
        publish_request(&spool, stale_uid, &request);
        spool.next_request(MAX_DOCUMENT_BYTES).unwrap().unwrap();
        spool.consume_request_new(stale_uid).unwrap();
        spool.write_ack_new(stale_uid, &ack).unwrap();
        assert_eq!(
            spool
                .consume_lifecycle_completion_proof(stale_uid, "quit")
                .unwrap_err()
                .code,
            "completion_proof_invalid"
        );

        let expired_uid = "61234567-89ab-4def-8123-456789abcdef";
        let (request, ack) = signed_finish_documents(
            &spool,
            expired_uid,
            now - 20,
            now - 10,
            now - 10,
            62,
            "start-62",
            "quit",
        );
        publish_request(&spool, expired_uid, &request);
        spool.next_request(MAX_DOCUMENT_BYTES).unwrap().unwrap();
        spool.consume_request_new(expired_uid).unwrap();
        spool.write_ack_new(expired_uid, &ack).unwrap();
        assert_eq!(
            spool
                .consume_lifecycle_completion_proof(expired_uid, "quit")
                .unwrap_err()
                .code,
            "completion_proof_invalid"
        );
    }

    #[test]
    fn corrupt_consumed_evidence_is_never_replaced_or_redispatched() {
        let base = base();
        let spool = DmuxBridgeSpool::open_at_base(base.path(), "gui-corrupt", 56, "start").unwrap();
        let uid = "11234567-89ab-4def-8123-456789abcdef";
        spool
            .consumed
            .write_new_atomic(&format!("req-{uid}.json"), b"not-json")
            .unwrap();
        publish_request(&spool, uid, b"valid-new-request");

        let error = spool.consume_request_new(uid).unwrap_err();
        assert_eq!(error.code, "already_consumed");
        assert_eq!(spool.read_consumed(uid, 64).unwrap().unwrap(), b"not-json");
        let (_, still_pending) = spool.next_request(64).unwrap().unwrap();
        assert_eq!(still_pending, b"valid-new-request");
        spool.discard_observed_request(uid).unwrap();
        assert!(spool.next_request(64).unwrap().is_none());
        assert_eq!(spool.read_consumed(uid, 64).unwrap().unwrap(), b"not-json");
    }

    #[test]
    fn request_inode_swap_and_lease_replacement_fail_closed() {
        let base = base();
        let spool = DmuxBridgeSpool::open_at_base(base.path(), "gui-race", 59, "start").unwrap();
        let uid = "31234567-89ab-4def-8123-456789abcdef";
        publish_request(&spool, uid, b"observed-request");
        let (_, observed) = spool.next_request(64).unwrap().unwrap();
        assert_eq!(observed, b"observed-request");

        let request_name = format!("req-{uid}.json");
        spool.requests.unlink(&request_name).unwrap();
        publish_request(&spool, uid, b"replacement-request");
        let error = spool.consume_request_new(uid).unwrap_err();
        assert_eq!(error.code, "request_changed");
        assert!(spool.read_consumed(uid, 64).unwrap().is_none());

        spool.instance_dir.unlink(LEASE_FILE).unwrap();
        spool
            .instance_dir
            .write_new_atomic(LEASE_FILE, b"replacement-lease")
            .unwrap();
        let error = spool.next_request(64).unwrap_err();
        assert_eq!(error.code, "lease_lost");
    }

    #[test]
    fn symlink_and_oversize_inputs_fail_closed() {
        let base = base();
        let spool = DmuxBridgeSpool::open_at_base(base.path(), "gui-hostile", 57, "start").unwrap();
        let uid = "21234567-89ab-4def-8123-456789abcdef";
        let target = base.path().join("target");
        fs::write(&target, b"target").unwrap();
        symlink(
            &target,
            spool.requests.display_path.join(format!("req-{uid}.json")),
        )
        .unwrap();
        let error = spool.next_request(64).unwrap_err();
        assert_eq!(error.code, "unsafe_file");
        fs::remove_file(spool.requests.display_path.join(format!("req-{uid}.json"))).unwrap();

        publish_request(&spool, uid, &vec![b'x'; 65]);
        let (_, body) = spool.next_request(64).unwrap().unwrap();
        assert_eq!(body.len(), 65, "one-byte overflow sentinel is preserved");
        spool.consume_request_new(uid).unwrap();
        assert_eq!(
            spool.read_consumed(uid, 64).unwrap_err().code,
            "message_too_large"
        );
    }

    #[test]
    fn context_reads_are_descriptor_relative_and_bounded() {
        let base = base();
        let spool = DmuxBridgeSpool::open_at_base(base.path(), "gui-context", 58, "start").unwrap();
        spool
            .context
            .write_new_atomic("42.json", b"context")
            .unwrap();
        assert_eq!(spool.read_context(42, 64).unwrap().unwrap(), b"context");
        assert!(spool.read_context(43, 64).unwrap().is_none());
        assert_eq!(
            spool.read_context(42, 3).unwrap_err().code,
            "message_too_large"
        );
    }

    #[test]
    fn untrusted_runtime_environment_overrides_are_ignored() {
        const PROBE: &str = "DMUX_WEZTERM_RUNTIME_ENV_PROBE";
        const EXPECTED: &str = "DMUX_WEZTERM_EXPECTED_RUNTIME_BASE";
        if std::env::var_os(PROBE).as_deref() == Some(std::ffi::OsStr::new("1")) {
            let resolved = platform_runtime_base().unwrap();
            let forbidden = PathBuf::from(std::env::var_os("DMUX_RUNTIME_DIR").unwrap());
            assert_ne!(resolved, forbidden);
            assert_ne!(resolved, PathBuf::from(std::env::var_os("TMPDIR").unwrap()));
            #[cfg(target_os = "linux")]
            assert_eq!(resolved, PathBuf::from(std::env::var_os(EXPECTED).unwrap()));
            return;
        }

        // Run the assertion in an isolated test process so changing process
        // environment cannot race other tests in this binary.
        let holder = tempfile::tempdir().unwrap();
        let trusted = holder.path().join("trusted-xdg");
        fs::create_dir(&trusted).unwrap();
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700)).unwrap();
        let forbidden = holder.path().join("attacker-override");
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("scripting::dmux_bridge::tests::untrusted_runtime_environment_overrides_are_ignored")
            .arg("--test-threads=1")
            .env(PROBE, "1")
            .env("DMUX_RUNTIME_DIR", &forbidden)
            .env("TMPDIR", &forbidden)
            .env("XDG_RUNTIME_DIR", &trusted)
            .env(EXPECTED, &trusted)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
