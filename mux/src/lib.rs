use crate::client::{ClientId, ClientInfo};
use crate::pane::{CachePolicy, Pane, PaneId};
use crate::ssh_agent::AgentProxy;
use crate::tab::{SplitRequest, Tab, TabId};
use crate::window::{Window, WindowId};
use anyhow::{anyhow, Context, Error};
use config::keyassignment::SpawnTabDomain;
use config::{configuration, ExitBehavior, GuiPosition};
use domain::{Domain, DomainId, DomainState, SplitSource};
use filedescriptor::{poll, pollfd, socketpair, AsRawSocketDescriptor, FileDescriptor, POLLIN};
#[cfg(unix)]
use libc::{c_int, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
use log::error;
use metrics::histogram;
use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
use percent_encoding::percent_decode_str;
use portable_pty::{CommandBuilder, ExitStatus, PtySize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};
use termwiz::escape::csi::{DecPrivateMode, DecPrivateModeCode, Device, Mode};
use termwiz::escape::{Action, CSI};
use thiserror::*;
use wezterm_term::{Clipboard, ClipboardSelection, DownloadHandler, TerminalSize};
#[cfg(windows)]
use winapi::um::winsock2::{SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};

pub mod activity;
pub mod client;
pub mod connui;
pub mod domain;
pub mod localpane;
pub mod pane;
pub mod renderable;
pub mod ssh;
pub mod ssh_agent;
pub mod tab;
pub mod termwiztermtab;
pub mod tmux;
pub mod tmux_commands;
mod tmux_pty;
pub mod window;

use crate::activity::Activity;

pub const DEFAULT_WORKSPACE: &str = "default";

#[derive(Clone, Debug)]
pub enum MuxNotification {
    PaneOutput(PaneId),
    PaneAdded(PaneId),
    PaneRemoved(PaneId),
    WindowCreated(WindowId),
    WindowRemoved(WindowId),
    WindowInvalidated(WindowId),
    WindowWorkspaceChanged(WindowId),
    ActiveWorkspaceChanged(Arc<ClientId>),
    Alert {
        pane_id: PaneId,
        alert: wezterm_term::Alert,
    },
    Empty,
    AssignClipboard {
        pane_id: PaneId,
        selection: ClipboardSelection,
        clipboard: Option<String>,
    },
    SaveToDownloads {
        name: Option<String>,
        data: Arc<Vec<u8>>,
    },
    TabAddedToWindow {
        tab_id: TabId,
        window_id: WindowId,
    },
    PaneFocused(PaneId),
    TabResized(TabId),
    TabTitleChanged {
        tab_id: TabId,
        title: String,
    },
    WindowTitleChanged {
        window_id: WindowId,
        title: String,
    },
    WorkspaceRenamed {
        old_workspace: String,
        new_workspace: String,
    },
}

static LAST_SUBSCRIBER_ID: AtomicUsize = AtomicUsize::new(0);

pub struct Mux {
    tabs: RwLock<HashMap<TabId, Arc<Tab>>>,
    panes: RwLock<HashMap<PaneId, Arc<dyn Pane>>>,
    windows: RwLock<HashMap<WindowId, Window>>,
    default_domain: RwLock<Option<Arc<dyn Domain>>>,
    domains: RwLock<HashMap<DomainId, Arc<dyn Domain>>>,
    domains_by_name: RwLock<HashMap<String, Arc<dyn Domain>>>,
    subscribers: RwLock<HashMap<usize, Box<dyn Fn(MuxNotification) -> bool + Send + Sync>>>,
    banner: RwLock<Option<String>>,
    clients: RwLock<HashMap<ClientId, ClientInfo>>,
    identity: RwLock<Option<Arc<ClientId>>>,
    num_panes_by_workspace: RwLock<HashMap<String, usize>>,
    main_thread_id: std::thread::ThreadId,
    agent: Option<AgentProxy>,
}

const BUFSIZE: usize = 1024 * 1024;

/// This function applies parsed actions to the pane and notifies any
/// mux subscribers about the output event
fn send_actions_to_mux(pane: &Weak<dyn Pane>, dead: &Arc<AtomicBool>, actions: Vec<Action>) {
    let start = Instant::now();
    match pane.upgrade() {
        Some(pane) => {
            pane.perform_actions(actions);
            histogram!("send_actions_to_mux.perform_actions.latency").record(start.elapsed());
            Mux::notify_from_any_thread(MuxNotification::PaneOutput(pane.pane_id()));
        }
        None => {
            // Something else removed the pane from
            // the mux, so signal that we should stop
            // trying to process it in read_from_pane_pty.
            dead.store(true, Ordering::Relaxed);
        }
    }
    histogram!("send_actions_to_mux.rate").record(1.);
}

/// This is the parsing loop for the given pane.
/// It reads all data sent to `rx` (from pane PTY) and handles all terminal events for this pane.
fn parse_buffered_data(pane: Weak<dyn Pane>, dead: &Arc<AtomicBool>, mut rx: FileDescriptor) {
    let mut buf = vec![0; configuration().mux_output_parser_buffer_size];
    let mut parser = termwiz::escape::parser::Parser::new();
    let mut actions = vec![];
    let mut hold = false;
    let mut action_size = 0;
    let mut delay = Duration::from_millis(configuration().mux_output_parser_coalesce_delay_ms);
    let mut deadline = None;

    loop {
        match rx.read(&mut buf) {
            Ok(size) if size == 0 => {
                dead.store(true, Ordering::Relaxed);
                break;
            }
            Err(_) => {
                dead.store(true, Ordering::Relaxed);
                break;
            }
            Ok(size) => {
                parser.parse(&buf[0..size], |action| {
                    let mut flush = false;
                    match &action {
                        Action::CSI(CSI::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
                            DecPrivateModeCode::SynchronizedOutput,
                        )))) => {
                            // Synchronized output frame started:
                            // => We hold off ~all actions that applies changes to the terminal.
                            hold = true;

                            // => We also flush prior actions
                            flush = true;
                        }
                        Action::CSI(CSI::Mode(Mode::ResetDecPrivateMode(
                            DecPrivateMode::Code(DecPrivateModeCode::SynchronizedOutput),
                        ))) => {
                            // Synchronized output frame ended:
                            // => We flush out all pending actions to the terminal.
                            hold = false;
                            flush = true;
                        }
                        Action::CSI(CSI::Device(dev)) if matches!(**dev, Device::SoftReset) => {
                            // Soft reset requested
                            hold = false;
                            flush = true;
                        }
                        _ => {}
                    };
                    action.append_to(&mut actions);

                    if flush && !actions.is_empty() {
                        send_actions_to_mux(&pane, &dead, std::mem::take(&mut actions));
                        action_size = 0;
                    }
                });
                action_size += size;
                if !actions.is_empty() && !hold {
                    // If we haven't accumulated too much data,
                    // pause for a short while to increase the chances
                    // that we coalesce a full "frame" from an unoptimized
                    // TUI program
                    if action_size < buf.len() {
                        let poll_delay = match deadline {
                            None => {
                                deadline.replace(Instant::now() + delay);
                                Some(delay)
                            }
                            Some(target) => target.checked_duration_since(Instant::now()),
                        };
                        if poll_delay.is_some() {
                            let mut pfd = [pollfd {
                                fd: rx.as_socket_descriptor(),
                                events: POLLIN,
                                revents: 0,
                            }];
                            if let Ok(1) = poll(&mut pfd, poll_delay) {
                                // We can read now without blocking, so accumulate
                                // more data into actions
                                continue;
                            }

                            // Not readable in time: let the data we have flow into
                            // the terminal model
                        }
                    }

                    send_actions_to_mux(&pane, &dead, std::mem::take(&mut actions));
                    deadline = None;
                    action_size = 0;
                }

                let config = configuration();
                buf.resize(config.mux_output_parser_buffer_size, 0);
                delay = Duration::from_millis(config.mux_output_parser_coalesce_delay_ms);
            }
        }
    }

    // Don't forget to send anything that we might have buffered
    // to be displayed before we return from here; this is important
    // for very short lived commands so that we don't forget to
    // display what they displayed.
    if !actions.is_empty() {
        send_actions_to_mux(&pane, &dead, std::mem::take(&mut actions));
    }
}

fn set_socket_buffer(fd: &mut FileDescriptor, option: i32, size: usize) -> anyhow::Result<()> {
    let size = size as c_int;
    let socklen = std::mem::size_of_val(&size);
    unsafe {
        let res = libc::setsockopt(
            fd.as_socket_descriptor(),
            SOL_SOCKET,
            option,
            &size as *const c_int as *const _,
            socklen as _,
        );
        if res == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()).context("setsockopt")
        }
    }
}

fn allocate_socketpair() -> anyhow::Result<(FileDescriptor, FileDescriptor)> {
    let (mut tx, mut rx) = socketpair().context("socketpair")?;
    set_socket_buffer(&mut tx, SO_SNDBUF, BUFSIZE)
        .context("SO_SNDBUF")
        .ok();
    set_socket_buffer(&mut rx, SO_RCVBUF, BUFSIZE)
        .context("SO_RCVBUF")
        .ok();
    Ok((tx, rx))
}

/// This function is run in a separate thread; its purpose is to perform
/// blocking reads from the pty (non-blocking reads are not portable to
/// all platforms and pty/tty types), parse the escape sequences and
/// relay the actions to the mux thread to apply them to the pane.
fn read_from_pane_pty(
    pane: Weak<dyn Pane>,
    banner: Option<String>,
    mut reader: Box<dyn std::io::Read>,
) {
    let mut buf = vec![0; BUFSIZE];

    // This is used to signal that an error occurred either in this thread,
    // or in the main mux thread.  If `true`, this thread will terminate.
    let dead = Arc::new(AtomicBool::new(false));

    let (pane_id, exit_behavior) = match pane.upgrade() {
        Some(pane) => (pane.pane_id(), pane.exit_behavior()),
        None => return,
    };

    let (mut tx, rx) = match allocate_socketpair() {
        Ok(pair) => pair,
        Err(err) => {
            log::error!("read_from_pane_pty: Unable to allocate a socketpair: {err:#}");
            localpane::emit_output_for_pane(
                pane_id,
                &format!(
                    "⚠️  wezterm: read_from_pane_pty: \
                    Unable to allocate a socketpair: {err:#}"
                ),
            );
            return;
        }
    };

    // Spawn parser thread for this pane
    std::thread::spawn({
        let dead = Arc::clone(&dead);
        move || parse_buffered_data(pane, &dead, rx)
    });

    if let Some(banner) = banner {
        tx.write_all(banner.as_bytes()).ok();
    }

    // Loop until the pane or the main mux thread is dead.
    // Read data from the pane pty and send it to the parser thread via tx/rx.
    while !dead.load(Ordering::Relaxed) {
        match reader.read(&mut buf) {
            Ok(size) if size == 0 => {
                log::trace!("read_pty EOF: pane_id {}", pane_id);
                break;
            }
            Err(err) => {
                error!("read_pty failed: pane {} {:?}", pane_id, err);
                break;
            }
            Ok(size) => {
                histogram!("read_from_pane_pty.bytes.rate").record(size as f64);
                log::trace!("read_pty pane {pane_id} read {size} bytes");
                // Send received data to this pane parser thread.
                if let Err(err) = tx.write_all(&buf[..size]) {
                    error!(
                        "read_pty failed to write to parser for pane {}: {:?}",
                        pane_id, err
                    );
                    break;
                }
            }
        }
    }

    match exit_behavior.unwrap_or_else(|| configuration().exit_behavior) {
        ExitBehavior::Hold | ExitBehavior::CloseOnCleanExit => {
            // We don't know if we can unilaterally close
            // this pane right now, so don't!
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::get();
                log::trace!("checking for dead windows after EOF on pane {}", pane_id);
                mux.prune_dead_windows();
            })
            .detach();
        }
        ExitBehavior::Close => {
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::get();
                mux.remove_pane(pane_id);
            })
            .detach();
        }
    }

    dead.store(true, Ordering::Relaxed);
}

lazy_static::lazy_static! {
    static ref MUX: Mutex<Option<Arc<Mux>>> = Mutex::new(None);
}

#[cfg(test)]
static TEST_MUX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct MuxWindowBuilder {
    window_id: WindowId,
    activity: Option<Activity>,
    notified: bool,
}

impl MuxWindowBuilder {
    fn notify(&mut self) {
        if self.notified {
            return;
        }
        self.notified = true;
        let activity = self.activity.take().unwrap();
        let window_id = self.window_id;
        let mux = Mux::get();
        if mux.is_main_thread() {
            // If we're already on the mux thread, just send the notification
            // immediately.
            // This is super important for Wayland; if we push it to the
            // spawn queue below then the extra milliseconds of delay
            // causes it to get confused and shutdown the connection!?
            mux.notify(MuxNotification::WindowCreated(window_id));
        } else {
            promise::spawn::spawn_into_main_thread(async move {
                if let Some(mux) = Mux::try_get() {
                    mux.notify(MuxNotification::WindowCreated(window_id));
                    drop(activity);
                }
            })
            .detach();
        }
    }
}

impl Drop for MuxWindowBuilder {
    fn drop(&mut self) {
        self.notify();
    }
}

impl std::ops::Deref for MuxWindowBuilder {
    type Target = WindowId;

    fn deref(&self) -> &WindowId {
        &self.window_id
    }
}

impl Mux {
    pub fn new(default_domain: Option<Arc<dyn Domain>>) -> Self {
        let mut domains = HashMap::new();
        let mut domains_by_name = HashMap::new();
        if let Some(default_domain) = default_domain.as_ref() {
            domains.insert(default_domain.domain_id(), Arc::clone(default_domain));

            domains_by_name.insert(
                default_domain.domain_name().to_string(),
                Arc::clone(default_domain),
            );
        }

        let agent = if config::configuration().mux_enable_ssh_agent {
            Some(AgentProxy::new())
        } else {
            None
        };

        Self {
            tabs: RwLock::new(HashMap::new()),
            panes: RwLock::new(HashMap::new()),
            windows: RwLock::new(HashMap::new()),
            default_domain: RwLock::new(default_domain),
            domains_by_name: RwLock::new(domains_by_name),
            domains: RwLock::new(domains),
            subscribers: RwLock::new(HashMap::new()),
            banner: RwLock::new(None),
            clients: RwLock::new(HashMap::new()),
            identity: RwLock::new(None),
            num_panes_by_workspace: RwLock::new(HashMap::new()),
            main_thread_id: std::thread::current().id(),
            agent,
        }
    }

    fn get_default_workspace(&self) -> String {
        let config = configuration();
        config
            .default_workspace
            .as_deref()
            .unwrap_or(DEFAULT_WORKSPACE)
            .to_string()
    }

    pub fn is_main_thread(&self) -> bool {
        std::thread::current().id() == self.main_thread_id
    }

    fn recompute_pane_count(&self) {
        let mut count = HashMap::new();
        for window in self.windows.read().values() {
            let workspace = window.get_workspace();
            for tab in window.iter() {
                *count.entry(workspace.to_string()).or_insert(0) += match tab.count_panes() {
                    Some(n) => n,
                    None => {
                        // Busy: abort this and we'll retry later
                        return;
                    }
                };
            }
        }
        *self.num_panes_by_workspace.write() = count;
    }

    pub fn client_had_input(&self, client_id: &ClientId) {
        if let Some(info) = self.clients.write().get_mut(client_id) {
            info.update_last_input();
        }
        if let Some(agent) = &self.agent {
            agent.update_target();
        }
    }

    pub fn record_input_for_current_identity(&self) {
        if let Some(ident) = self.identity.read().as_ref() {
            self.client_had_input(ident);
        }
    }

    pub fn record_focus_for_current_identity(&self, pane_id: PaneId) {
        if let Some(ident) = self.identity.read().as_ref() {
            self.record_focus_for_client(ident, pane_id);
        }
    }

    pub fn resolve_focused_pane(
        &self,
        client_id: &ClientId,
    ) -> Option<(DomainId, WindowId, TabId, PaneId)> {
        let pane_id = self.clients.read().get(client_id)?.focused_pane_id?;
        let (domain, window, tab) = self.resolve_pane_id(pane_id)?;
        Some((domain, window, tab, pane_id))
    }

    pub fn record_focus_for_client(&self, client_id: &ClientId, pane_id: PaneId) {
        let mut prior = None;
        if let Some(info) = self.clients.write().get_mut(client_id) {
            prior = info.focused_pane_id;
            info.update_focused_pane(pane_id);
        }

        if prior == Some(pane_id) {
            return;
        }
        // Synthesize focus events
        if let Some(prior_id) = prior {
            if let Some(pane) = self.get_pane(prior_id) {
                pane.focus_changed(false);
            }
        }
        if let Some(pane) = self.get_pane(pane_id) {
            pane.focus_changed(true);
        }
    }

    /// Called by PaneFocused event handlers to reconcile a remote
    /// pane focus event and apply its effects locally
    pub fn focus_pane_and_containing_tab(&self, pane_id: PaneId) -> anyhow::Result<()> {
        let pane = self
            .get_pane(pane_id)
            .ok_or_else(|| anyhow::anyhow!("pane {pane_id} not found"))?;

        let (_domain, window_id, tab_id) = self
            .resolve_pane_id(pane_id)
            .ok_or_else(|| anyhow::anyhow!("can't find {pane_id} in the mux"))?;

        // Focus/activate the containing tab within its window
        {
            let mut win = self
                .get_window_mut(window_id)
                .ok_or_else(|| anyhow::anyhow!("window_id {window_id} not found"))?;
            let tab_idx = win
                .idx_by_id(tab_id)
                .ok_or_else(|| anyhow::anyhow!("tab {tab_id} not in {window_id}"))?;
            win.save_and_then_set_active(tab_idx);
        }

        // Focus/activate the pane locally
        let tab = self
            .get_tab(tab_id)
            .ok_or_else(|| anyhow::anyhow!("tab {tab_id} not found"))?;

        tab.set_active_pane(&pane);

        Ok(())
    }

    pub fn register_client(&self, client_id: Arc<ClientId>) {
        self.clients
            .write()
            .insert((*client_id).clone(), ClientInfo::new(client_id));
    }

    pub fn iter_clients(&self) -> Vec<ClientInfo> {
        self.clients
            .read()
            .values()
            .map(|info| info.clone())
            .collect()
    }

    /// Returns a list of the unique workspace names known to the mux.
    /// This is taken from all known windows.
    pub fn iter_workspaces(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .windows
            .read()
            .values()
            .map(|w| w.get_workspace().to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Generate a new unique workspace name
    pub fn generate_workspace_name(&self) -> String {
        let used = self.iter_workspaces();
        for candidate in names::Generator::default() {
            if !used.contains(&candidate) {
                return candidate;
            }
        }
        unreachable!();
    }

    /// Returns the effective active workspace name
    pub fn active_workspace(&self) -> String {
        self.identity
            .read()
            .as_ref()
            .and_then(|ident| {
                self.clients
                    .read()
                    .get(&ident)
                    .and_then(|info| info.active_workspace.clone())
            })
            .unwrap_or_else(|| self.get_default_workspace())
    }

    /// Returns the effective active workspace name for a given client
    pub fn active_workspace_for_client(&self, ident: &Arc<ClientId>) -> String {
        self.clients
            .read()
            .get(&ident)
            .and_then(|info| info.active_workspace.clone())
            .unwrap_or_else(|| self.get_default_workspace())
    }

    pub fn set_active_workspace_for_client(&self, ident: &Arc<ClientId>, workspace: &str) {
        let mut clients = self.clients.write();
        if let Some(info) = clients.get_mut(&ident) {
            info.active_workspace.replace(workspace.to_string());
            self.notify(MuxNotification::ActiveWorkspaceChanged(ident.clone()));
        }
    }

    /// Assigns the active workspace name for the current identity
    pub fn set_active_workspace(&self, workspace: &str) {
        if let Some(ident) = self.identity.read().clone() {
            self.set_active_workspace_for_client(&ident, workspace);
        }
    }

    pub fn rename_workspace(&self, old_workspace: &str, new_workspace: &str) {
        if old_workspace == new_workspace {
            return;
        }
        self.notify(MuxNotification::WorkspaceRenamed {
            old_workspace: old_workspace.to_string(),
            new_workspace: new_workspace.to_string(),
        });

        for window in self.windows.write().values_mut() {
            if window.get_workspace() == old_workspace {
                window.set_workspace(new_workspace);
            }
        }
        self.recompute_pane_count();
        for client in self.clients.write().values_mut() {
            if client.active_workspace.as_deref() == Some(old_workspace) {
                client.active_workspace.replace(new_workspace.to_string());
                self.notify(MuxNotification::ActiveWorkspaceChanged(
                    client.client_id.clone(),
                ));
            }
        }
    }

    /// Compare-and-swap rename of a single window's workspace.
    ///
    /// Verifies that `window_id` exists and currently has workspace
    /// `expected_workspace`, then assigns `new_workspace` to that window
    /// alone.  When `expect_sole_window` is true it additionally requires
    /// that no other window shares `expected_workspace` at execution time.
    /// All of the checks and the rename itself happen under a single
    /// write lock over the window map (and, in practice, serialized on
    /// the mux main thread with every other PDU handler), so the
    /// precondition cannot be invalidated between check and swap.
    ///
    /// On `Err`, no mutation has been performed: the window map, every
    /// client's active workspace and the per-workspace pane counts are
    /// unchanged, and no notification is emitted.
    ///
    /// On success the rename is observable exactly like the stock
    /// window-scoped rename (`Pdu::SetWindowWorkspace`):
    /// `Window::set_workspace` emits
    /// `MuxNotification::WindowWorkspaceChanged(window_id)`, which the
    /// mux server dispatcher forwards to attached clients.  As a special
    /// case, renaming to the name the window already holds is a
    /// successful no-op that emits no notification, which makes retrying
    /// an already-applied rename idempotent.
    ///
    /// When `expect_sole_window` is true, a successful rename has
    /// provably migrated the entire `expected_workspace` name, so clients
    /// whose active workspace was `expected_workspace` are retargeted to
    /// `new_workspace` with `MuxNotification::ActiveWorkspaceChanged`,
    /// mirroring `Mux::rename_workspace` semantics.  In non-sole mode
    /// that retargeting is deliberately skipped, matching
    /// `SetWindowWorkspace` semantics.
    pub fn rename_workspace_for_window_if(
        &self,
        window_id: WindowId,
        expected_workspace: &str,
        new_workspace: &str,
        expect_sole_window: bool,
    ) -> Result<(), WorkspaceCasError> {
        {
            let mut windows = self.windows.write();

            let actual = match windows.get(&window_id) {
                Some(window) => window.get_workspace().to_string(),
                None => return Err(WorkspaceCasError::NoSuchWindow),
            };
            if actual != expected_workspace {
                return Err(WorkspaceCasError::WorkspaceMismatch { actual });
            }

            if expect_sole_window {
                let other_window_ids: Vec<WindowId> = windows
                    .values()
                    .filter(|w| {
                        w.window_id() != window_id && w.get_workspace() == expected_workspace
                    })
                    .map(|w| w.window_id())
                    .collect();
                if !other_window_ids.is_empty() {
                    return Err(WorkspaceCasError::NotSoleWindow { other_window_ids });
                }
            }

            windows
                .get_mut(&window_id)
                .expect("checked above under the same write lock")
                .set_workspace(new_workspace);
        }

        self.recompute_pane_count();

        if expect_sole_window && expected_workspace != new_workspace {
            // The expected workspace name is proven to have fully migrated
            // to `new_workspace`, so retarget clients that were following
            // the old name, mirroring `rename_workspace` semantics
            // (including its equal-name early return, which keeps the
            // idempotent-retry case a true no-op).
            for client in self.clients.write().values_mut() {
                if client.active_workspace.as_deref() == Some(expected_workspace) {
                    client.active_workspace.replace(new_workspace.to_string());
                    self.notify(MuxNotification::ActiveWorkspaceChanged(
                        client.client_id.clone(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Overrides the current client identity.
    /// Returns `IdentityHolder` which will restore the prior identity
    /// when it is dropped.
    /// This can be used to change the identity for the duration of a block.
    pub fn with_identity(&self, id: Option<Arc<ClientId>>) -> IdentityHolder {
        let prior = self.replace_identity(id);
        IdentityHolder { prior }
    }

    /// Replace the identity, returning the prior identity
    pub fn replace_identity(&self, id: Option<Arc<ClientId>>) -> Option<Arc<ClientId>> {
        std::mem::replace(&mut *self.identity.write(), id)
    }

    /// Returns the active identity
    pub fn active_identity(&self) -> Option<Arc<ClientId>> {
        self.identity.read().clone()
    }

    pub fn unregister_client(&self, client_id: &ClientId) {
        self.clients.write().remove(client_id);
    }

    pub fn subscribe<F>(&self, subscriber: F)
    where
        F: Fn(MuxNotification) -> bool + 'static + Send + Sync,
    {
        let sub_id = LAST_SUBSCRIBER_ID.fetch_add(1, Ordering::Relaxed);
        self.subscribers
            .write()
            .insert(sub_id, Box::new(subscriber));
    }

    pub fn notify(&self, notification: MuxNotification) {
        let mut subscribers = self.subscribers.write();
        subscribers.retain(|_, notify| notify(notification.clone()));
    }

    pub fn notify_from_any_thread(notification: MuxNotification) {
        if let Some(mux) = Mux::try_get() {
            if mux.is_main_thread() {
                mux.notify(notification);
                return;
            }
        }
        promise::spawn::spawn_into_main_thread(async {
            if let Some(mux) = Mux::try_get() {
                mux.notify(notification);
            }
        })
        .detach();
    }

    pub fn default_domain(&self) -> Arc<dyn Domain> {
        self.default_domain.read().as_ref().map(Arc::clone).unwrap()
    }

    pub fn set_default_domain(&self, domain: &Arc<dyn Domain>) {
        *self.default_domain.write() = Some(Arc::clone(domain));
    }

    pub fn get_domain(&self, id: DomainId) -> Option<Arc<dyn Domain>> {
        self.domains.read().get(&id).cloned()
    }

    pub fn get_domain_by_name(&self, name: &str) -> Option<Arc<dyn Domain>> {
        self.domains_by_name.read().get(name).cloned()
    }

    pub fn add_domain(&self, domain: &Arc<dyn Domain>) {
        if self.default_domain.read().is_none() {
            *self.default_domain.write() = Some(Arc::clone(domain));
        }
        self.domains
            .write()
            .insert(domain.domain_id(), Arc::clone(domain));
        self.domains_by_name
            .write()
            .insert(domain.domain_name().to_string(), Arc::clone(domain));
    }

    pub fn set_mux(mux: &Arc<Mux>) {
        MUX.lock().replace(Arc::clone(mux));
    }

    pub fn shutdown() {
        MUX.lock().take();
    }

    pub fn get() -> Arc<Mux> {
        Self::try_get().unwrap()
    }

    pub fn try_get() -> Option<Arc<Mux>> {
        MUX.lock().as_ref().map(Arc::clone)
    }

    pub fn get_pane(&self, pane_id: PaneId) -> Option<Arc<dyn Pane>> {
        self.panes.read().get(&pane_id).map(Arc::clone)
    }

    pub fn get_tab(&self, tab_id: TabId) -> Option<Arc<Tab>> {
        self.tabs.read().get(&tab_id).map(Arc::clone)
    }

    pub fn add_pane(&self, pane: &Arc<dyn Pane>) -> Result<(), Error> {
        if self.panes.read().contains_key(&pane.pane_id()) {
            return Ok(());
        }

        let clipboard: Arc<dyn Clipboard> = Arc::new(MuxClipboard {
            pane_id: pane.pane_id(),
        });
        pane.set_clipboard(&clipboard);

        let downloader: Arc<dyn DownloadHandler> = Arc::new(MuxDownloader {});
        pane.set_download_handler(&downloader);

        self.panes.write().insert(pane.pane_id(), Arc::clone(pane));
        let pane_id = pane.pane_id();
        if let Some(reader) = pane.reader()? {
            let banner = self.banner.read().clone();
            let pane = Arc::downgrade(pane);
            thread::spawn(move || read_from_pane_pty(pane, banner, reader));
        }
        self.recompute_pane_count();
        self.notify(MuxNotification::PaneAdded(pane_id));
        Ok(())
    }

    pub fn add_tab_no_panes(&self, tab: &Arc<Tab>) {
        self.tabs.write().insert(tab.tab_id(), Arc::clone(tab));
        self.recompute_pane_count();
    }

    pub fn add_tab_and_active_pane(&self, tab: &Arc<Tab>) -> Result<(), Error> {
        self.tabs.write().insert(tab.tab_id(), Arc::clone(tab));
        let pane = tab
            .get_active_pane()
            .ok_or_else(|| anyhow!("tab MUST have an active pane"))?;
        self.add_pane(&pane)
    }

    fn remove_pane_internal(&self, pane_id: PaneId) {
        log::debug!("removing pane {}", pane_id);
        let mut changed = false;
        if let Some(pane) = self.panes.write().remove(&pane_id).clone() {
            log::debug!("killing pane {}", pane_id);
            pane.kill();
            self.notify(MuxNotification::PaneRemoved(pane_id));
            changed = true;
        }

        if changed {
            self.recompute_pane_count();
        }
    }

    fn remove_tab_internal(&self, tab_id: TabId) -> Option<Arc<Tab>> {
        log::debug!("remove_tab_internal tab {}", tab_id);

        let tab = self.tabs.write().remove(&tab_id)?;

        if let Some(mut windows) = self.windows.try_write() {
            for w in windows.values_mut() {
                w.remove_by_id(tab_id);
            }
        }

        let mut pane_ids = vec![];
        for pos in tab.iter_panes_ignoring_zoom() {
            pane_ids.push(pos.pane.pane_id());
        }
        log::debug!("panes to remove: {pane_ids:?}");
        for pane_id in pane_ids {
            self.remove_pane_internal(pane_id);
        }
        self.recompute_pane_count();

        Some(tab)
    }

    fn remove_window_internal(&self, window_id: WindowId) {
        log::debug!("remove_window_internal {}", window_id);

        let window = self.windows.write().remove(&window_id);
        if let Some(window) = window {
            // Gather all the domains referenced by this window
            let mut domains_of_window = HashSet::new();
            for tab in window.iter() {
                for pane in tab.iter_panes_ignoring_zoom() {
                    domains_of_window.insert(pane.pane.domain_id());
                }
            }

            for domain_id in domains_of_window {
                if let Some(domain) = self.get_domain(domain_id) {
                    if domain.detachable() {
                        log::info!("detaching domain");
                        if let Err(err) = domain.detach() {
                            log::error!(
                                "while detaching domain {domain_id} {}: {err:#}",
                                domain.domain_name()
                            );
                        }
                    }
                }
            }

            for tab in window.iter() {
                self.remove_tab_internal(tab.tab_id());
            }
            self.notify(MuxNotification::WindowRemoved(window_id));
        }
        self.recompute_pane_count();
    }

    /// Recovery removes only the exact window and its descendants.  The
    /// stock window-close path may detach a whole detachable domain, which
    /// could remove panes belonging to neighboring windows and is therefore
    /// deliberately not used by exact crash reconciliation.
    fn remove_window_internal_for_recovery(&self, window_id: WindowId) {
        let window = self.windows.write().remove(&window_id);
        if let Some(window) = window {
            let tab_ids: Vec<_> = window.iter().map(|tab| tab.tab_id()).collect();
            for tab_id in tab_ids {
                self.remove_tab_internal(tab_id);
            }
            self.notify(MuxNotification::WindowRemoved(window_id));
        }
        self.recompute_pane_count();
    }

    pub fn remove_pane(&self, pane_id: PaneId) {
        self.remove_pane_internal(pane_id);
        self.prune_dead_windows();
    }

    pub fn remove_tab(&self, tab_id: TabId) -> Option<Arc<Tab>> {
        let tab = self.remove_tab_internal(tab_id);
        self.prune_dead_windows();
        tab
    }

    pub fn prune_dead_windows(&self) {
        if Activity::count() > 0 {
            log::trace!("prune_dead_windows: Activity::count={}", Activity::count());
            return;
        }
        let live_tab_ids: Vec<TabId> = self.tabs.read().keys().cloned().collect();
        let mut dead_windows = vec![];
        let dead_tab_ids: Vec<TabId>;

        {
            let mut windows = match self.windows.try_write() {
                Some(w) => w,
                None => {
                    // It's ok if our caller already locked it; we can prune later.
                    log::trace!("prune_dead_windows: self.windows already borrowed");
                    return;
                }
            };
            for (window_id, win) in windows.iter_mut() {
                win.prune_dead_tabs(&live_tab_ids);
                if win.is_empty() {
                    log::trace!("prune_dead_windows: window is now empty");
                    dead_windows.push(*window_id);
                }
            }

            dead_tab_ids = self
                .tabs
                .read()
                .iter()
                .filter_map(|(&id, tab)| if tab.is_dead() { Some(id) } else { None })
                .collect();
        }

        for tab_id in dead_tab_ids {
            log::trace!("tab {} is dead", tab_id);
            self.remove_tab_internal(tab_id);
        }

        for window_id in dead_windows {
            log::trace!("window {} is dead", window_id);
            self.remove_window_internal(window_id);
        }

        if self.is_empty() {
            log::trace!("prune_dead_windows: is_empty, send MuxNotification::Empty");
            self.notify(MuxNotification::Empty);
        } else {
            log::trace!("prune_dead_windows: not empty");
        }
    }

    pub fn kill_window(&self, window_id: WindowId) {
        self.remove_window_internal(window_id);
        self.prune_dead_windows();
    }

    /// Remove one exact native node for fenced dmux crash reconciliation.
    ///
    /// This deliberately avoids `prune_dead_windows`: broad pruning could
    /// remove an unrelated dead neighbor. Empty ancestors of the exact node
    /// are instead cascaded synchronously and included in the typed outcome.
    pub fn remove_recovery_node_exact(
        &self,
        target: RecoveryRemoveTarget,
    ) -> RecoveryRemoveOutcome {
        let kind = target.kind();
        let requested_native_id = target.native_id();
        let mut outcome = RecoveryRemoveOutcome::new(kind, requested_native_id);

        let before_panes: HashSet<PaneId> = self.panes.read().keys().copied().collect();
        let before_tabs: HashSet<TabId> = self.tabs.read().keys().copied().collect();
        let before_windows: HashSet<WindowId> = self.windows.read().keys().copied().collect();

        match target {
            RecoveryRemoveTarget::Pane {
                pane_id,
                parent_tab_id,
                parent_window_id,
            } => {
                if self.get_pane(pane_id).is_none() {
                    outcome.status = RecoveryRemoveStatus::NotFound;
                    return outcome;
                }

                let (_domain_id, actual_window_id, actual_tab_id) =
                    match self.resolve_pane_id(pane_id) {
                        Some(ids) => ids,
                        None => {
                            outcome.status = RecoveryRemoveStatus::ParentMismatch;
                            return outcome;
                        }
                    };
                outcome.actual_parent_tab_id = Some(actual_tab_id);
                outcome.actual_parent_window_id = Some(actual_window_id);
                if actual_tab_id != parent_tab_id || actual_window_id != parent_window_id {
                    outcome.status = RecoveryRemoveStatus::ParentMismatch;
                    return outcome;
                }

                let tab = match self.get_tab(actual_tab_id) {
                    Some(tab) => tab,
                    None => {
                        outcome.status = RecoveryRemoveStatus::ParentMismatch;
                        return outcome;
                    }
                };
                let pane_count = tab.iter_panes_ignoring_zoom().len();
                let tab_count = self
                    .get_window(actual_window_id)
                    .map(|window| window.len())
                    .unwrap_or(0);

                outcome.removed_pane_ids.push(pane_id);
                if pane_count == 1 {
                    outcome.removed_tab_ids.push(actual_tab_id);
                    if tab_count == 1 {
                        outcome.removed_window_ids.push(actual_window_id);
                    }
                }

                if tab.remove_pane(pane_id).is_none() {
                    outcome.status = RecoveryRemoveStatus::PostconditionFailed;
                    outcome.removed_pane_ids.clear();
                    outcome.removed_tab_ids.clear();
                    outcome.removed_window_ids.clear();
                    outcome.postcondition_error = Some(
                        "pane disappeared from its validated parent before removal".to_string(),
                    );
                    return outcome;
                }
                self.remove_pane_internal(pane_id);

                if pane_count == 1 {
                    self.remove_tab_internal(actual_tab_id);
                    if tab_count == 1 {
                        self.remove_window_internal_for_recovery(actual_window_id);
                    }
                }
            }
            RecoveryRemoveTarget::Tab {
                tab_id,
                parent_window_id,
            } => {
                let tab = match self.get_tab(tab_id) {
                    Some(tab) => tab,
                    None => {
                        outcome.status = RecoveryRemoveStatus::NotFound;
                        return outcome;
                    }
                };
                let actual_window_id = match self.window_containing_tab(tab_id) {
                    Some(window_id) => window_id,
                    None => {
                        outcome.status = RecoveryRemoveStatus::ParentMismatch;
                        return outcome;
                    }
                };
                outcome.actual_parent_window_id = Some(actual_window_id);
                if actual_window_id != parent_window_id {
                    outcome.status = RecoveryRemoveStatus::ParentMismatch;
                    return outcome;
                }

                outcome.removed_pane_ids = tab
                    .iter_panes_ignoring_zoom()
                    .into_iter()
                    .map(|pane| pane.pane.pane_id())
                    .collect();
                outcome.removed_tab_ids.push(tab_id);
                let tab_count = self
                    .get_window(actual_window_id)
                    .map(|window| window.len())
                    .unwrap_or(0);
                if tab_count == 1 {
                    outcome.removed_window_ids.push(actual_window_id);
                }

                self.remove_tab_internal(tab_id);
                if tab_count == 1 {
                    self.remove_window_internal_for_recovery(actual_window_id);
                }
            }
            RecoveryRemoveTarget::Window {
                window_id,
                workspace,
            } => {
                let window = match self.get_window(window_id) {
                    Some(window) => window,
                    None => {
                        outcome.status = RecoveryRemoveStatus::NotFound;
                        return outcome;
                    }
                };
                let actual_workspace = window.get_workspace().to_string();
                outcome.actual_workspace = Some(actual_workspace.clone());
                if actual_workspace != workspace {
                    outcome.status = RecoveryRemoveStatus::ParentMismatch;
                    return outcome;
                }

                for tab in window.iter() {
                    outcome.removed_tab_ids.push(tab.tab_id());
                    for pane in tab.iter_panes_ignoring_zoom() {
                        outcome.removed_pane_ids.push(pane.pane.pane_id());
                    }
                }
                drop(window);
                outcome.removed_window_ids.push(window_id);
                self.remove_window_internal_for_recovery(window_id);
            }
        }

        outcome.sort_removed_ids();
        let expected_panes: HashSet<_> = outcome.removed_pane_ids.iter().copied().collect();
        let expected_tabs: HashSet<_> = outcome.removed_tab_ids.iter().copied().collect();
        let expected_windows: HashSet<_> = outcome.removed_window_ids.iter().copied().collect();
        let after_panes: HashSet<PaneId> = self.panes.read().keys().copied().collect();
        let after_tabs: HashSet<TabId> = self.tabs.read().keys().copied().collect();
        let after_windows: HashSet<WindowId> = self.windows.read().keys().copied().collect();

        let target_still_present = expected_panes.iter().any(|id| after_panes.contains(id))
            || expected_tabs.iter().any(|id| after_tabs.contains(id))
            || expected_windows.iter().any(|id| after_windows.contains(id));
        let neighbor_missing = before_panes
            .difference(&expected_panes)
            .any(|id| !after_panes.contains(id))
            || before_tabs
                .difference(&expected_tabs)
                .any(|id| !after_tabs.contains(id))
            || before_windows
                .difference(&expected_windows)
                .any(|id| !after_windows.contains(id));

        outcome.removed_pane_ids = before_panes.difference(&after_panes).copied().collect();
        outcome.removed_tab_ids = before_tabs.difference(&after_tabs).copied().collect();
        outcome.removed_window_ids = before_windows.difference(&after_windows).copied().collect();
        outcome.sort_removed_ids();

        if target_still_present || neighbor_missing {
            outcome.status = RecoveryRemoveStatus::PostconditionFailed;
            outcome.postcondition_error = Some(format!(
                "target_still_present={target_still_present} neighboring_node_missing={neighbor_missing}"
            ));
        } else {
            outcome.status = RecoveryRemoveStatus::Removed;
        }
        outcome
    }

    pub fn get_window(&self, window_id: WindowId) -> Option<MappedRwLockReadGuard<'_, Window>> {
        if !self.windows.read().contains_key(&window_id) {
            return None;
        }
        Some(RwLockReadGuard::map(self.windows.read(), |windows| {
            windows.get(&window_id).unwrap()
        }))
    }

    pub fn get_window_mut(
        &self,
        window_id: WindowId,
    ) -> Option<MappedRwLockWriteGuard<'_, Window>> {
        if !self.windows.read().contains_key(&window_id) {
            return None;
        }
        Some(RwLockWriteGuard::map(self.windows.write(), |windows| {
            windows.get_mut(&window_id).unwrap()
        }))
    }

    pub fn get_active_tab_for_window(&self, window_id: WindowId) -> Option<Arc<Tab>> {
        let window = self.get_window(window_id)?;
        window.get_active().map(Arc::clone)
    }

    pub fn new_empty_window(
        &self,
        workspace: Option<String>,
        position: Option<GuiPosition>,
    ) -> MuxWindowBuilder {
        let window = Window::new(workspace, position);
        let window_id = window.window_id();
        self.windows.write().insert(window_id, window);
        MuxWindowBuilder {
            window_id,
            activity: Some(Activity::new()),
            notified: false,
        }
    }

    pub fn add_tab_to_window(&self, tab: &Arc<Tab>, window_id: WindowId) -> anyhow::Result<()> {
        let tab_id = tab.tab_id();
        {
            let mut window = self
                .get_window_mut(window_id)
                .ok_or_else(|| anyhow!("add_tab_to_window: no such window_id {}", window_id))?;
            window.push(tab);
        }
        self.recompute_pane_count();
        self.notify(MuxNotification::TabAddedToWindow { tab_id, window_id });
        Ok(())
    }

    /// Returns the ID of the window containing the given tab ID, if any.
    pub fn window_containing_tab(&self, tab_id: TabId) -> Option<WindowId> {
        for w in self.windows.read().values() {
            for t in w.iter() {
                if t.tab_id() == tab_id {
                    return Some(w.window_id());
                }
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.panes.read().is_empty()
    }

    pub fn is_workspace_empty(&self, workspace: &str) -> bool {
        *self
            .num_panes_by_workspace
            .read()
            .get(workspace)
            .unwrap_or(&0)
            == 0
    }

    pub fn is_active_workspace_empty(&self) -> bool {
        let workspace = self.active_workspace();
        self.is_workspace_empty(&workspace)
    }

    pub fn iter_panes(&self) -> Vec<Arc<dyn Pane>> {
        self.panes
            .read()
            .iter()
            .map(|(_, v)| Arc::clone(v))
            .collect()
    }

    pub fn iter_windows_in_workspace(&self, workspace: &str) -> Vec<WindowId> {
        let mut windows: Vec<WindowId> = self
            .windows
            .read()
            .iter()
            .filter_map(|(k, w)| {
                if w.get_workspace() == workspace {
                    Some(k)
                } else {
                    None
                }
            })
            .cloned()
            .collect();
        windows.sort();
        windows
    }

    pub fn iter_windows(&self) -> Vec<WindowId> {
        self.windows.read().keys().cloned().collect()
    }

    pub fn iter_domains(&self) -> Vec<Arc<dyn Domain>> {
        self.domains.read().values().cloned().collect()
    }

    pub fn resolve_pane_id(&self, pane_id: PaneId) -> Option<(DomainId, WindowId, TabId)> {
        let mut ids = None;
        for tab in self.tabs.read().values() {
            for p in tab.iter_panes_ignoring_zoom() {
                if p.pane.pane_id() == pane_id {
                    ids = Some((tab.tab_id(), p.pane.domain_id()));
                    break;
                }
            }
        }
        let (tab_id, domain_id) = ids?;
        let window_id = self.window_containing_tab(tab_id)?;
        Some((domain_id, window_id, tab_id))
    }

    pub fn domain_was_detached(&self, domain: DomainId) {
        let mut dead_panes = vec![];
        for pane in self.panes.read().values() {
            if pane.domain_id() == domain {
                dead_panes.push(pane.pane_id());
            }
        }

        {
            let mut windows = self.windows.write();
            for (_, win) in windows.iter_mut() {
                for tab in win.iter() {
                    tab.kill_panes_in_domain(domain);
                }
            }
        }

        log::info!("domain detached panes: {:?}", dead_panes);
        for pane_id in dead_panes {
            self.remove_pane_internal(pane_id);
        }

        self.prune_dead_windows();
    }

    pub fn set_banner(&self, banner: Option<String>) {
        *self.banner.write() = banner;
    }

    pub fn resolve_spawn_tab_domain(
        &self,
        // TODO: disambiguate with TabId
        pane_id: Option<PaneId>,
        domain: &config::keyassignment::SpawnTabDomain,
    ) -> anyhow::Result<Arc<dyn Domain>> {
        let domain = match domain {
            SpawnTabDomain::DefaultDomain => self.default_domain(),
            SpawnTabDomain::CurrentPaneDomain => match pane_id {
                Some(pane_id) => {
                    let (pane_domain_id, _window_id, _tab_id) = self
                        .resolve_pane_id(pane_id)
                        .ok_or_else(|| anyhow!("pane_id {} invalid", pane_id))?;
                    self.get_domain(pane_domain_id)
                        .expect("resolve_pane_id to give valid domain_id")
                }
                None => self.default_domain(),
            },
            SpawnTabDomain::DomainId(domain_id) => self
                .get_domain(*domain_id)
                .ok_or_else(|| anyhow!("domain id {} is invalid", domain_id))?,
            SpawnTabDomain::DomainName(name) => {
                self.get_domain_by_name(&name).ok_or_else(|| {
                    let names: Vec<String> = self
                        .domains_by_name
                        .read()
                        .keys()
                        .map(|name| format!("\"{name}\""))
                        .collect();
                    anyhow!(
                        "domain name \"{name}\" is invalid. Possible names are {}.",
                        names.join(", ")
                    )
                })?
            }
        };
        Ok(domain)
    }

    fn resolve_cwd(
        &self,
        command_dir: Option<String>,
        pane: Option<Arc<dyn Pane>>,
        target_domain: DomainId,
        policy: CachePolicy,
    ) -> Option<String> {
        command_dir.or_else(|| {
            match pane {
                Some(pane) if pane.domain_id() == target_domain => pane
                    .get_current_working_dir(policy)
                    .and_then(|url| {
                        percent_decode_str(url.path())
                            .decode_utf8()
                            .ok()
                            .map(|path| path.into_owned())
                    })
                    .map(|path| {
                        // On Windows the file URI can produce a path like:
                        // `/C:\Users` which is valid in a file URI, but the leading slash
                        // is not liked by the windows file APIs, so we strip it off here.
                        let bytes = path.as_bytes();
                        if bytes.len() > 2 && bytes[0] == b'/' && bytes[2] == b':' {
                            path[1..].to_owned()
                        } else {
                            path
                        }
                    }),
                _ => None,
            }
        })
    }

    pub async fn split_pane(
        &self,
        // TODO: disambiguate with TabId
        pane_id: PaneId,
        request: SplitRequest,
        source: SplitSource,
        domain: config::keyassignment::SpawnTabDomain,
    ) -> anyhow::Result<(Arc<dyn Pane>, TerminalSize)> {
        let (_pane_domain_id, window_id, tab_id) = self
            .resolve_pane_id(pane_id)
            .ok_or_else(|| anyhow!("pane_id {} invalid", pane_id))?;

        let domain = self
            .resolve_spawn_tab_domain(Some(pane_id), &domain)
            .context("resolve_spawn_tab_domain")?;

        if domain.state() == DomainState::Detached {
            domain.attach(Some(window_id)).await?;
        }

        let current_pane = self
            .get_pane(pane_id)
            .ok_or_else(|| anyhow!("pane_id {} is invalid", pane_id))?;
        let term_config = current_pane.get_config();

        let source = match source {
            SplitSource::Spawn {
                command,
                command_dir,
            } => SplitSource::Spawn {
                command,
                command_dir: self.resolve_cwd(
                    command_dir,
                    Some(Arc::clone(&current_pane)),
                    domain.domain_id(),
                    CachePolicy::FetchImmediate,
                ),
            },
            other => other,
        };

        let pane = domain.split_pane(source, tab_id, pane_id, request).await?;
        if let Some(config) = term_config {
            pane.set_config(config);
        }

        // FIXME: clipboard

        let dims = pane.get_dimensions();

        let size = TerminalSize {
            cols: dims.cols,
            rows: dims.viewport_rows,
            pixel_height: 0, // FIXME: split pane pixel dimensions
            pixel_width: 0,
            dpi: dims.dpi,
        };

        Ok((pane, size))
    }

    pub async fn move_pane_to_new_tab(
        &self,
        pane_id: PaneId,
        window_id: Option<WindowId>,
        workspace_for_new_window: Option<String>,
    ) -> anyhow::Result<(Arc<Tab>, WindowId)> {
        let (domain_id, _src_window, src_tab) = self
            .resolve_pane_id(pane_id)
            .ok_or_else(|| anyhow::anyhow!("pane {} not found", pane_id))?;

        let domain = self
            .get_domain(domain_id)
            .ok_or_else(|| anyhow::anyhow!("domain {domain_id} of pane {pane_id} not found"))?;

        if let Some((tab, window_id)) = domain
            .move_pane_to_new_tab(pane_id, window_id, workspace_for_new_window.clone())
            .await?
        {
            return Ok((tab, window_id));
        }

        let src_tab = match self.get_tab(src_tab) {
            Some(t) => t,
            None => anyhow::bail!("Invalid tab id {}", src_tab),
        };

        let window_builder;
        let (window_id, size) = if let Some(window_id) = window_id {
            let window = self
                .get_window_mut(window_id)
                .ok_or_else(|| anyhow!("window_id {} not found on this server", window_id))?;
            let tab = window
                .get_active()
                .ok_or_else(|| anyhow!("window {} has no tabs", window_id))?;
            let size = tab.get_size();

            (window_id, size)
        } else {
            window_builder = self.new_empty_window(workspace_for_new_window, None);
            (*window_builder, src_tab.get_size())
        };

        let pane = src_tab
            .remove_pane(pane_id)
            .ok_or_else(|| anyhow::anyhow!("pane {} wasn't in its containing tab!?", pane_id))?;

        let tab = Arc::new(Tab::new(&size));
        tab.assign_pane(&pane);
        pane.resize(size)?;
        self.add_tab_and_active_pane(&tab)?;
        self.add_tab_to_window(&tab, window_id)?;

        if src_tab.is_dead() {
            self.remove_tab(src_tab.tab_id());
        }

        Ok((tab, window_id))
    }

    pub async fn spawn_tab_or_window(
        &self,
        window_id: Option<WindowId>,
        domain: SpawnTabDomain,
        command: Option<CommandBuilder>,
        command_dir: Option<String>,
        size: TerminalSize,
        current_pane_id: Option<PaneId>,
        workspace_for_new_window: String,
        window_position: Option<GuiPosition>,
    ) -> anyhow::Result<(Arc<Tab>, Arc<dyn Pane>, WindowId)> {
        let domain = self
            .resolve_spawn_tab_domain(current_pane_id, &domain)
            .context("resolve_spawn_tab_domain")?;

        let window_builder;
        let term_config;

        let (window_id, size) = if let Some(window_id) = window_id {
            let window = self
                .get_window_mut(window_id)
                .ok_or_else(|| anyhow!("window_id {} not found on this server", window_id))?;
            let tab = window
                .get_active()
                .ok_or_else(|| anyhow!("window {} has no tabs", window_id))?;
            let pane = tab
                .get_active_pane()
                .ok_or_else(|| anyhow!("active tab in window {} has no panes", window_id))?;
            term_config = pane.get_config();

            let size = tab.get_size();

            (window_id, size)
        } else {
            term_config = None;
            window_builder = self.new_empty_window(Some(workspace_for_new_window), window_position);
            (*window_builder, size)
        };

        if domain.state() == DomainState::Detached {
            domain.attach(Some(window_id)).await?;
        }

        let cwd = self.resolve_cwd(
            command_dir,
            match current_pane_id {
                Some(id) => {
                    // Only use the cwd from the current pane if the domain
                    // is the same as the one we are spawning into
                    let (current_domain_id, _, _) = self
                        .resolve_pane_id(id)
                        .ok_or_else(|| anyhow!("pane_id {} invalid", id))?;
                    if current_domain_id == domain.domain_id() {
                        self.get_pane(id)
                    } else {
                        None
                    }
                }
                None => None,
            },
            domain.domain_id(),
            CachePolicy::FetchImmediate,
        );

        let tab = domain
            .spawn(size, command.clone(), cwd.clone(), window_id)
            .await
            .with_context(|| {
                format!(
                    "Spawning in domain `{}`: {size:?} command={command:?} cwd={cwd:?}",
                    domain.domain_name()
                )
            })?;

        let pane = tab
            .get_active_pane()
            .ok_or_else(|| anyhow!("missing active pane on tab!?"))?;

        if let Some(config) = term_config {
            pane.set_config(config);
        }

        // FIXME: clipboard?

        let mut window = self
            .get_window_mut(window_id)
            .ok_or_else(|| anyhow!("no such window!?"))?;
        if let Some(idx) = window.idx_by_id(tab.tab_id()) {
            window.save_and_then_set_active(idx);
        }

        Ok((tab, pane, window_id))
    }
}

/// Failure modes of [`Mux::rename_workspace_for_window_if`].
/// Every variant guarantees that no mutation was performed.
/// The `Display` spellings match the stable failure tokens that
/// `wezterm cli rename-workspace --window-id` reports on stderr.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WorkspaceCasError {
    /// No window with the requested id exists
    #[error("no_such_window")]
    NoSuchWindow,
    /// The window exists but is in a different workspace
    #[error("workspace_mismatch actual={actual:?}")]
    WorkspaceMismatch { actual: String },
    /// `expect_sole_window` was requested but other windows share
    /// the expected workspace
    #[error("not_sole_window other_window_ids={other_window_ids:?}")]
    NotSoleWindow { other_window_ids: Vec<WindowId> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryNodeKind {
    Pane,
    Tab,
    Window,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryRemoveTarget {
    Pane {
        pane_id: PaneId,
        parent_tab_id: TabId,
        parent_window_id: WindowId,
    },
    Tab {
        tab_id: TabId,
        parent_window_id: WindowId,
    },
    Window {
        window_id: WindowId,
        workspace: String,
    },
}

impl RecoveryRemoveTarget {
    pub fn kind(&self) -> RecoveryNodeKind {
        match self {
            Self::Pane { .. } => RecoveryNodeKind::Pane,
            Self::Tab { .. } => RecoveryNodeKind::Tab,
            Self::Window { .. } => RecoveryNodeKind::Window,
        }
    }

    pub fn native_id(&self) -> usize {
        match self {
            Self::Pane { pane_id, .. } => *pane_id,
            Self::Tab { tab_id, .. } => *tab_id,
            Self::Window { window_id, .. } => *window_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRemoveStatus {
    Removed,
    NotFound,
    ParentMismatch,
    PostconditionFailed,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecoveryRemoveOutcome {
    pub schema_version: u8,
    pub status: RecoveryRemoveStatus,
    pub kind: RecoveryNodeKind,
    pub requested_native_id: usize,
    pub actual_parent_tab_id: Option<TabId>,
    pub actual_parent_window_id: Option<WindowId>,
    pub actual_workspace: Option<String>,
    pub removed_pane_ids: Vec<PaneId>,
    pub removed_tab_ids: Vec<TabId>,
    pub removed_window_ids: Vec<WindowId>,
    pub postcondition_error: Option<String>,
}

impl RecoveryRemoveOutcome {
    pub fn new(kind: RecoveryNodeKind, requested_native_id: usize) -> Self {
        Self {
            schema_version: 1,
            status: RecoveryRemoveStatus::PostconditionFailed,
            kind,
            requested_native_id,
            actual_parent_tab_id: None,
            actual_parent_window_id: None,
            actual_workspace: None,
            removed_pane_ids: vec![],
            removed_tab_ids: vec![],
            removed_window_ids: vec![],
            postcondition_error: None,
        }
    }

    fn sort_removed_ids(&mut self) {
        self.removed_pane_ids.sort_unstable();
        self.removed_tab_ids.sort_unstable();
        self.removed_window_ids.sort_unstable();
    }
}

pub struct IdentityHolder {
    prior: Option<Arc<ClientId>>,
}

impl Drop for IdentityHolder {
    fn drop(&mut self) {
        if let Some(mux) = Mux::try_get() {
            mux.replace_identity(self.prior.take());
        }
    }
}

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum SessionTerminated {
    #[error("Process exited: {:?}", status)]
    ProcessStatus { status: ExitStatus },
    #[error("Error: {:?}", err)]
    Error { err: Error },
    #[error("Window Closed")]
    WindowClosed,
}

pub(crate) fn terminal_size_to_pty_size(size: TerminalSize) -> anyhow::Result<PtySize> {
    Ok(PtySize {
        rows: size.rows.try_into()?,
        cols: size.cols.try_into()?,
        pixel_height: size.pixel_height.try_into()?,
        pixel_width: size.pixel_width.try_into()?,
    })
}

struct MuxClipboard {
    pane_id: PaneId,
}

impl Clipboard for MuxClipboard {
    fn set_contents(
        &self,
        selection: ClipboardSelection,
        clipboard: Option<String>,
    ) -> anyhow::Result<()> {
        let mux =
            Mux::try_get().ok_or_else(|| anyhow::anyhow!("MuxClipboard::set_contents: no Mux?"))?;
        mux.notify(MuxNotification::AssignClipboard {
            pane_id: self.pane_id,
            selection,
            clipboard,
        });
        Ok(())
    }
}

struct MuxDownloader {}

impl wezterm_term::DownloadHandler for MuxDownloader {
    fn save_to_downloads(&self, name: Option<String>, data: Vec<u8>) {
        if let Some(mux) = Mux::try_get() {
            mux.notify(MuxNotification::SaveToDownloads {
                name,
                data: Arc::new(data),
            });
        }
    }
}

#[cfg(test)]
mod cas_rename_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Install a process-global Mux suitable for in-process unit tests:
    /// no default domain, and the ssh agent proxy disabled so that
    /// `Mux::new` has no filesystem or thread side effects.
    fn test_mux() -> Arc<Mux> {
        let mut config = config::Config::default();
        config.mux_enable_ssh_agent = false;
        config::use_this_configuration(config);
        let mux = Arc::new(Mux::new(None));
        Mux::set_mux(&mux);
        mux
    }

    fn add_window(mux: &Mux, workspace: &str) -> WindowId {
        let window = Window::new(Some(workspace.to_string()), None);
        let window_id = window.window_id();
        mux.windows.write().insert(window_id, window);
        window_id
    }

    fn workspace_of(mux: &Mux, window_id: WindowId) -> String {
        mux.windows
            .read()
            .get(&window_id)
            .expect("window should exist")
            .get_workspace()
            .to_string()
    }

    /// Covers all four `rename_workspace_for_window_if` outcomes
    /// (Renamed / NoSuchWindow / WorkspaceMismatch / NotSoleWindow),
    /// the zero-mutation guarantee of every failure, the notifications
    /// emitted on success, sole-window client retargeting, and the
    /// idempotent-retry no-op.  A single test function keeps use of the
    /// process-global `Mux` deterministic under the parallel test runner.
    #[test]
    fn rename_workspace_for_window_if_outcomes() {
        let _serial = TEST_MUX_LOCK.lock().unwrap();
        let mux = test_mux();

        // Capture workspace-related notifications.  Other tests in this
        // crate could in principle share the process-global mux, so
        // assertions below match on the specific ids created here.
        let observed: Arc<StdMutex<Vec<MuxNotification>>> = Arc::new(StdMutex::new(vec![]));
        {
            let observed = Arc::clone(&observed);
            mux.subscribe(move |n| {
                if matches!(
                    n,
                    MuxNotification::WindowWorkspaceChanged(_)
                        | MuxNotification::ActiveWorkspaceChanged(_)
                        | MuxNotification::WorkspaceRenamed { .. }
                ) {
                    observed.lock().unwrap().push(n);
                }
                true
            });
        }
        fn drain(observed: &StdMutex<Vec<MuxNotification>>) -> Vec<MuxNotification> {
            std::mem::take(&mut *observed.lock().unwrap())
        }

        let win_a = add_window(&mux, "source");

        // A client following the source workspace, to observe
        // sole-window retargeting.
        let client_id = Arc::new(ClientId::new());
        {
            let mut clients = mux.clients.write();
            let mut info = ClientInfo::new(Arc::clone(&client_id));
            info.active_workspace.replace("source".to_string());
            clients.insert((*client_id).clone(), info);
        }
        let active_workspace_of_client = |mux: &Mux| -> Option<String> {
            mux.clients
                .read()
                .get(&client_id)
                .expect("client should exist")
                .active_workspace
                .clone()
        };

        // NoSuchWindow: nothing mutated, nothing notified.
        assert_eq!(
            mux.rename_workspace_for_window_if(WindowId::MAX, "source", "dest", false),
            Err(WorkspaceCasError::NoSuchWindow)
        );
        assert_eq!(workspace_of(&mux, win_a), "source");
        assert!(drain(&observed).is_empty());

        // WorkspaceMismatch reports the actual workspace name:
        // nothing mutated, nothing notified.
        assert_eq!(
            mux.rename_workspace_for_window_if(win_a, "stale-expectation", "dest", false),
            Err(WorkspaceCasError::WorkspaceMismatch {
                actual: "source".to_string()
            })
        );
        assert_eq!(workspace_of(&mux, win_a), "source");
        assert!(drain(&observed).is_empty());

        // NotSoleWindow lists the interloping windows:
        // nothing mutated, nothing notified.
        let win_b = add_window(&mux, "source");
        assert_eq!(
            mux.rename_workspace_for_window_if(win_a, "source", "dest", true),
            Err(WorkspaceCasError::NotSoleWindow {
                other_window_ids: vec![win_b]
            })
        );
        assert_eq!(workspace_of(&mux, win_a), "source");
        assert_eq!(workspace_of(&mux, win_b), "source");
        assert!(drain(&observed).is_empty());

        // Renamed without expect_sole_window: the interloper does not
        // block, only the named window moves, and the stock
        // WindowWorkspaceChanged notification fires for exactly that
        // window.  The client keeps following "source"
        // (SetWindowWorkspace semantics).
        assert_eq!(
            mux.rename_workspace_for_window_if(win_b, "source", "elsewhere", false),
            Ok(())
        );
        assert_eq!(workspace_of(&mux, win_b), "elsewhere");
        assert_eq!(workspace_of(&mux, win_a), "source");
        let notifs = drain(&observed);
        assert_eq!(notifs.len(), 1, "unexpected notifications: {notifs:?}");
        assert!(matches!(
            notifs[0],
            MuxNotification::WindowWorkspaceChanged(id) if id == win_b
        ));
        assert_eq!(active_workspace_of_client(&mux), Some("source".to_string()));

        // Renamed with expect_sole_window: the window moves, the stock
        // notification fires, and the client following the fully
        // migrated name is retargeted with ActiveWorkspaceChanged
        // (rename_workspace semantics).
        assert_eq!(
            mux.rename_workspace_for_window_if(win_a, "source", "dmux:host:space", true),
            Ok(())
        );
        assert_eq!(workspace_of(&mux, win_a), "dmux:host:space");
        assert_eq!(
            active_workspace_of_client(&mux),
            Some("dmux:host:space".to_string())
        );
        let notifs = drain(&observed);
        assert_eq!(notifs.len(), 2, "unexpected notifications: {notifs:?}");
        assert!(matches!(
            notifs[0],
            MuxNotification::WindowWorkspaceChanged(id) if id == win_a
        ));
        assert!(matches!(
            &notifs[1],
            MuxNotification::ActiveWorkspaceChanged(id) if **id == *client_id
        ));

        // Renaming to the name the window already holds, with a correct
        // expectation, is an idempotent success (the retry of an applied
        // rename): no mutation, no notification.
        assert_eq!(
            mux.rename_workspace_for_window_if(win_a, "dmux:host:space", "dmux:host:space", true),
            Ok(())
        );
        assert_eq!(workspace_of(&mux, win_a), "dmux:host:space");
        assert!(drain(&observed).is_empty());
    }
}

#[cfg(test)]
mod recovery_remove_tests {
    use super::*;
    use crate::pane::{ForEachPaneLogicalLine, LogicalLine, WithPaneLines};
    use crate::renderable::*;
    use parking_lot::{MappedMutexGuard, Mutex as ParkingMutex};
    use rangeset::RangeSet;
    use std::ops::Range;
    use termwiz::surface::{Line, SequenceNo};
    use url::Url;
    use wezterm_term::color::ColorPalette;
    use wezterm_term::{KeyCode, KeyModifiers, MouseEvent, StableRowIndex};

    struct FakePane {
        id: PaneId,
        size: ParkingMutex<TerminalSize>,
    }

    impl FakePane {
        fn new(id: PaneId, size: TerminalSize) -> Arc<dyn Pane> {
            Arc::new(Self {
                id,
                size: ParkingMutex::new(size),
            })
        }
    }

    impl Pane for FakePane {
        fn pane_id(&self) -> PaneId {
            self.id
        }

        fn get_cursor_position(&self) -> StableCursorPosition {
            unimplemented!()
        }

        fn get_current_seqno(&self) -> SequenceNo {
            unimplemented!()
        }

        fn get_changed_since(
            &self,
            _lines: Range<StableRowIndex>,
            _seqno: SequenceNo,
        ) -> RangeSet<StableRowIndex> {
            unimplemented!()
        }

        fn with_lines_mut(
            &self,
            _stable_range: Range<StableRowIndex>,
            _with_lines: &mut dyn WithPaneLines,
        ) {
            unimplemented!()
        }

        fn for_each_logical_line_in_stable_range_mut(
            &self,
            _lines: Range<StableRowIndex>,
            _for_line: &mut dyn ForEachPaneLogicalLine,
        ) {
            unimplemented!()
        }

        fn get_lines(&self, _lines: Range<StableRowIndex>) -> (StableRowIndex, Vec<Line>) {
            unimplemented!()
        }

        fn get_logical_lines(&self, _lines: Range<StableRowIndex>) -> Vec<LogicalLine> {
            unimplemented!()
        }

        fn get_dimensions(&self) -> RenderableDimensions {
            unimplemented!()
        }

        fn get_title(&self) -> String {
            format!("fake-pane-{}", self.id)
        }

        fn send_paste(&self, _text: &str) -> anyhow::Result<()> {
            unimplemented!()
        }

        fn reader(&self) -> anyhow::Result<Option<Box<dyn std::io::Read + Send>>> {
            Ok(None)
        }

        fn writer(&self) -> MappedMutexGuard<'_, dyn std::io::Write> {
            unimplemented!()
        }

        fn resize(&self, size: TerminalSize) -> anyhow::Result<()> {
            *self.size.lock() = size;
            Ok(())
        }

        fn key_down(&self, _key: KeyCode, _mods: KeyModifiers) -> anyhow::Result<()> {
            unimplemented!()
        }

        fn key_up(&self, _key: KeyCode, _mods: KeyModifiers) -> anyhow::Result<()> {
            unimplemented!()
        }

        fn mouse_event(&self, _event: MouseEvent) -> anyhow::Result<()> {
            unimplemented!()
        }

        fn is_dead(&self) -> bool {
            false
        }

        fn palette(&self) -> ColorPalette {
            unimplemented!()
        }

        fn domain_id(&self) -> DomainId {
            1
        }

        fn is_mouse_grabbed(&self) -> bool {
            false
        }

        fn is_alt_screen_active(&self) -> bool {
            false
        }

        fn get_current_working_dir(&self, _policy: CachePolicy) -> Option<Url> {
            None
        }
    }

    fn test_mux() -> Arc<Mux> {
        let mut config = config::Config::default();
        config.mux_enable_ssh_agent = false;
        config::use_this_configuration(config);
        let mux = Arc::new(Mux::new(None));
        Mux::set_mux(&mux);
        mux
    }

    fn test_size() -> TerminalSize {
        TerminalSize {
            rows: 24,
            cols: 80,
            pixel_width: 800,
            pixel_height: 600,
            dpi: 96,
        }
    }

    fn add_window(mux: &Mux, workspace: &str) -> WindowId {
        let window = Window::new(Some(workspace.to_string()), None);
        let window_id = window.window_id();
        mux.windows.write().insert(window_id, window);
        window_id
    }

    fn add_tab(mux: &Mux, window_id: WindowId, pane_ids: &[PaneId]) -> TabId {
        assert!(!pane_ids.is_empty());
        let size = test_size();
        let tab = Arc::new(Tab::new(&size));
        let mut panes = Vec::new();
        for (index, pane_id) in pane_ids.iter().copied().enumerate() {
            let pane = FakePane::new(pane_id, size);
            if index == 0 {
                tab.assign_pane(&pane);
            } else {
                tab.split_and_insert(0, SplitRequest::default(), Arc::clone(&pane))
                    .unwrap();
            }
            panes.push(pane);
        }
        mux.add_tab_no_panes(&tab);
        for pane in panes {
            mux.add_pane(&pane).unwrap();
        }
        mux.add_tab_to_window(&tab, window_id).unwrap();
        tab.tab_id()
    }

    /// Exercises the typed exact-id outcomes in one serialized test because
    /// Mux is process-global: exact pane/tab/window success, parent mismatch,
    /// idempotent not-found, root-pane cascade, and neighbor preservation.
    #[test]
    fn exact_recovery_removal_outcomes_and_cascades() {
        let _serial = TEST_MUX_LOCK.lock().unwrap();
        let mux = test_mux();

        let primary_window = add_window(&mux, "dmux:space:primary");
        let split_tab = add_tab(&mux, primary_window, &[1001, 1002]);
        let neighbor_tab = add_tab(&mux, primary_window, &[1003]);

        let pane_outcome = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Pane {
            pane_id: 1001,
            parent_tab_id: split_tab,
            parent_window_id: primary_window,
        });
        assert_eq!(pane_outcome.status, RecoveryRemoveStatus::Removed);
        assert_eq!(pane_outcome.removed_pane_ids, vec![1001]);
        assert!(pane_outcome.removed_tab_ids.is_empty());
        assert!(pane_outcome.removed_window_ids.is_empty());
        assert!(mux.get_pane(1001).is_none());
        assert!(mux.get_pane(1002).is_some());
        assert!(mux.get_pane(1003).is_some());
        assert!(mux.get_tab(split_tab).is_some());
        assert!(mux.get_tab(neighbor_tab).is_some());
        assert!(mux.get_window(primary_window).is_some());

        let mismatch = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Pane {
            pane_id: 1002,
            parent_tab_id: neighbor_tab,
            parent_window_id: primary_window,
        });
        assert_eq!(mismatch.status, RecoveryRemoveStatus::ParentMismatch);
        assert_eq!(mismatch.actual_parent_tab_id, Some(split_tab));
        assert!(mismatch.removed_pane_ids.is_empty());
        assert!(mux.get_pane(1002).is_some());
        assert!(mux.get_pane(1003).is_some());

        let missing = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Pane {
            pane_id: usize::MAX,
            parent_tab_id: split_tab,
            parent_window_id: primary_window,
        });
        assert_eq!(missing.status, RecoveryRemoveStatus::NotFound);
        assert!(missing.removed_pane_ids.is_empty());
        assert!(missing.removed_tab_ids.is_empty());
        assert!(missing.removed_window_ids.is_empty());

        let tab_outcome = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Tab {
            tab_id: neighbor_tab,
            parent_window_id: primary_window,
        });
        assert_eq!(tab_outcome.status, RecoveryRemoveStatus::Removed);
        assert_eq!(tab_outcome.removed_pane_ids, vec![1003]);
        assert_eq!(tab_outcome.removed_tab_ids, vec![neighbor_tab]);
        assert!(tab_outcome.removed_window_ids.is_empty());
        assert!(mux.get_pane(1002).is_some());
        assert!(mux.get_tab(split_tab).is_some());
        assert!(mux.get_window(primary_window).is_some());

        let root_window = add_window(&mux, "dmux:space:root-cascade");
        let root_tab = add_tab(&mux, root_window, &[1004]);
        let root_outcome = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Pane {
            pane_id: 1004,
            parent_tab_id: root_tab,
            parent_window_id: root_window,
        });
        assert_eq!(root_outcome.status, RecoveryRemoveStatus::Removed);
        assert_eq!(root_outcome.removed_pane_ids, vec![1004]);
        assert_eq!(root_outcome.removed_tab_ids, vec![root_tab]);
        assert_eq!(root_outcome.removed_window_ids, vec![root_window]);
        assert!(mux.get_pane(1004).is_none());
        assert!(mux.get_tab(root_tab).is_none());
        assert!(mux.get_window(root_window).is_none());
        assert!(mux.get_pane(1002).is_some(), "neighbor pane was removed");

        let window_to_remove = add_window(&mux, "dmux:space:window-remove");
        let window_tab_a = add_tab(&mux, window_to_remove, &[1005]);
        let window_tab_b = add_tab(&mux, window_to_remove, &[1006]);
        let wrong_workspace = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Window {
            window_id: window_to_remove,
            workspace: "dmux:space:wrong".to_string(),
        });
        assert_eq!(wrong_workspace.status, RecoveryRemoveStatus::ParentMismatch);
        assert!(wrong_workspace.removed_window_ids.is_empty());
        assert!(mux.get_window(window_to_remove).is_some());
        assert!(mux.get_pane(1005).is_some());
        assert!(mux.get_pane(1006).is_some());

        let window_outcome = mux.remove_recovery_node_exact(RecoveryRemoveTarget::Window {
            window_id: window_to_remove,
            workspace: "dmux:space:window-remove".to_string(),
        });
        assert_eq!(window_outcome.status, RecoveryRemoveStatus::Removed);
        assert_eq!(window_outcome.removed_pane_ids, vec![1005, 1006]);
        assert_eq!(
            window_outcome.removed_tab_ids,
            vec![window_tab_a, window_tab_b]
        );
        assert_eq!(window_outcome.removed_window_ids, vec![window_to_remove]);
        assert!(mux.get_window(window_to_remove).is_none());
        assert!(mux.get_tab(window_tab_a).is_none());
        assert!(mux.get_tab(window_tab_b).is_none());
        assert!(mux.get_pane(1005).is_none());
        assert!(mux.get_pane(1006).is_none());
        assert!(mux.get_pane(1002).is_some(), "neighbor pane was removed");
        assert!(mux.get_window(primary_window).is_some());
    }
}
