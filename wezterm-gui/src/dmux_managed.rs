use config::keyassignment::{KeyAssignment, PaneSelectMode};
use config::UnixDomain;
use std::ffi::OsStr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseRequestDisposition {
    FollowStandardPolicy,
    RefuseAndNotifyBroker,
}

pub(crate) fn close_request_disposition(dmux_managed_gui: bool) -> CloseRequestDisposition {
    if dmux_managed_gui {
        CloseRequestDisposition::RefuseAndNotifyBroker
    } else {
        CloseRequestDisposition::FollowStandardPolicy
    }
}

/// Returns true when an action must not be exposed by a managed dmux GUI.
///
/// In addition to direct resource creation and native application lifecycle,
/// this excludes owner-layout mutations and uncorrelated workspace switches.
/// Those transitions are brokered by dmux so that it can revalidate logical
/// markers, journal mutations, and prove that owner-side panes survived.
pub(crate) fn is_forbidden_ui_action(action: &KeyAssignment) -> bool {
    use KeyAssignment::*;

    match action {
        SpawnTab(_)
        | SpawnWindow
        | SpawnCommandInNewTab(_)
        | SpawnCommandInNewWindow(_)
        | SplitHorizontal(_)
        | SplitVertical(_)
        | SplitPane(_)
        | AttachDomain(_)
        | DetachDomain(_)
        | SwitchToWorkspace { .. }
        | SwitchWorkspaceRelative(_)
        | MoveTab(_)
        | MoveTabRelative(_)
        | AdjustPaneSize(_, _)
        | TogglePaneZoomState
        | SetPaneZoomState(_)
        | RotatePanes(_)
        | CloseCurrentTab { .. }
        | CloseCurrentPane { .. }
        | HideApplication
        | QuitApplication
        | ReloadConfiguration => true,
        PaneSelect(args) => match args.mode {
            PaneSelectMode::Activate => false,
            PaneSelectMode::SwapWithActive
            | PaneSelectMode::SwapWithActiveKeepFocus
            | PaneSelectMode::MoveToNewTab
            | PaneSelectMode::MoveToNewWindow => true,
        },
        Multiple(actions) => actions.iter().any(is_forbidden_ui_action),
        QuickSelectArgs(args) => args.action.as_deref().map_or(false, is_forbidden_ui_action),
        PromptInputLine(prompt) => is_forbidden_ui_action(&prompt.action),
        InputSelector(selector) => is_forbidden_ui_action(&selector.action),
        Confirmation(confirmation) => {
            is_forbidden_ui_action(&confirmation.action)
                || confirmation
                    .cancel
                    .as_deref()
                    .map_or(false, is_forbidden_ui_action)
        }
        // Presentation-only actions over already imported objects. Keep this
        // list exhaustive so a new KeyAssignment variant cannot silently
        // become available in managed mode without an explicit review.
        ToggleFullScreen
        | ToggleAlwaysOnTop
        | ToggleAlwaysOnBottom
        | SetWindowLevel(_)
        | CopyTo(_)
        | CopyTextTo { .. }
        | PasteFrom(_)
        | ActivateTabRelative(_)
        | ActivateTabRelativeNoWrap(_)
        | IncreaseFontSize
        | DecreaseFontSize
        | ResetFontSize
        | ResetFontAndWindowSize
        | ActivateTab(_)
        | ActivateLastTab
        | SendString(_)
        | SendKey(_)
        | Nop
        | DisableDefaultAssignment
        | Hide
        | Show
        | ScrollByPage(_)
        | ScrollByLine(_)
        | ScrollByCurrentEventWheelDelta
        | ScrollToPrompt(_)
        | ScrollToTop
        | ScrollToBottom
        | ShowTabNavigator
        | ShowDebugOverlay
        | ShowLauncher
        | ShowLauncherArgs(_)
        | ClearScrollback(_)
        | Search(_)
        | ActivateCopyMode
        | SelectTextAtMouseCursor(_)
        | ExtendSelectionToMouseCursor(_)
        | OpenLinkAtMouseCursor
        | ClearSelection
        | CompleteSelection(_)
        | CompleteSelectionOrOpenLinkAtMouseCursor(_)
        | StartWindowDrag
        | ActivatePaneDirection(_)
        | ActivatePaneByIndex(_)
        | EmitEvent(_)
        | QuickSelect
        | ActivateKeyTable { .. }
        | PopKeyTable
        | ClearKeyTableStack
        | CopyMode(_)
        | CharSelect(_)
        | ResetTerminal
        | OpenUri(_)
        | ActivateCommandPalette
        | ActivateWindow(_)
        | ActivateWindowRelative(_)
        | ActivateWindowRelativeNoWrap(_) => false,
    }
}

pub(crate) fn should_expose_ui_action(dmux_managed_gui: bool, action: &KeyAssignment) -> bool {
    !dmux_managed_gui || !is_forbidden_ui_action(action)
}

/// Runtime counterpart to [`should_expose_ui_action`].
///
/// Surface filtering is only a convenience: actions can also arrive from
/// Lua, native application callbacks, mouse handlers, or stale modal state.
/// Callers must consult this before giving either a modal or a pane a chance
/// to interpret the assignment.
pub(crate) fn should_perform_native_action(dmux_managed_gui: bool, action: &KeyAssignment) -> bool {
    !dmux_managed_gui || !is_forbidden_ui_action(action)
}

pub(crate) fn should_close_tab_directly(dmux_managed_gui: bool) -> bool {
    !dmux_managed_gui
}

pub(crate) fn should_reload_gui_configuration(dmux_managed_gui: bool) -> bool {
    !dmux_managed_gui
}

pub(crate) fn require_existing_panes_after_managed_attach(
    dmux_managed_gui: bool,
    is_connecting: bool,
    have_panes: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !dmux_managed_gui || !is_connecting || have_panes,
        "dmux-managed attach found no existing pane; refusing WezTerm's default-pane fallback"
    );
    Ok(())
}

pub(crate) fn require_managed_safe_quit_api(dmux_managed_gui: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        dmux_managed_gui,
        "dmux_safe_quit_application is available only when dmux_managed_gui is enabled"
    );
    Ok(())
}

pub(crate) fn require_managed_safe_hide_api(dmux_managed_gui: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        dmux_managed_gui,
        "dmux_safe_hide_application is available only when dmux_managed_gui is enabled"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedGuiStartupInvocation<'a> {
    Connect {
        domain: &'a str,
        new_tab: bool,
        has_workspace: bool,
        has_prog: bool,
    },
    Start {
        domain: Option<&'a str>,
        attach: bool,
        always_new_process: bool,
        new_tab: bool,
        has_prog: bool,
        has_cwd: bool,
        has_workspace: bool,
    },
    NativeCreate,
}

/// Reject WezTerm's load-error fallback before it can create the initial mux.
///
/// Config loading deliberately retains the last/default configuration on an
/// error.  That is desirable for stock WezTerm, but in wez-first mode it
/// would turn a missing/starting service descriptor into a local shell.
pub(crate) fn require_successful_managed_config_load(
    wez_first_requested: bool,
    config_error: Option<&str>,
) -> anyhow::Result<()> {
    if !wez_first_requested {
        return Ok(());
    }
    if let Some(error) = config_error {
        anyhow::bail!(
            "dmux wez-first startup refused because the managed configuration failed to load: {error}"
        );
    }
    Ok(())
}

/// Validate the fixed attach-only startup contract before `build_initial_mux`.
///
/// This does not replace dmux's descriptor/sentinel proof.  The broker still
/// performs that proof before exec and supplies the exact socket as
/// `WEZTERM_UNIX_SOCKET`; this gate makes sure that the successfully loaded
/// GUI config consumes that same socket without any native spawn path.
pub(crate) fn require_managed_startup_contract(
    wez_first_requested: bool,
    dmux_managed_gui: bool,
    default_gui_startup_args: &[String],
    unix_domains: &[UnixDomain],
    broker_socket: Option<&OsStr>,
    invocation: ManagedGuiStartupInvocation<'_>,
) -> anyhow::Result<()> {
    if !wez_first_requested {
        return Ok(());
    }

    anyhow::ensure!(
        dmux_managed_gui,
        "dmux wez-first startup refused because dmux_managed_gui is not enabled"
    );
    anyhow::ensure!(
        default_gui_startup_args == ["connect", "dmux"],
        "dmux wez-first startup refused because default_gui_startup_args is not attach-only"
    );
    anyhow::ensure!(
        unix_domains.len() == 1,
        "dmux wez-first startup refused because the managed config must declare exactly one unix domain"
    );

    let domain = &unix_domains[0];
    let socket = domain.socket_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("dmux wez-first startup refused because the dmux domain has no socket")
    })?;
    let broker_socket = broker_socket.map(Path::new).ok_or_else(|| {
        anyhow::anyhow!(
            "dmux wez-first startup refused because the broker did not provide WEZTERM_UNIX_SOCKET"
        )
    })?;
    anyhow::ensure!(
        domain.name == "dmux"
            && socket.is_absolute()
            && socket == broker_socket
            && domain.no_serve_automatically
            && !domain.connect_automatically
            && domain.serve_command.is_none()
            && domain.proxy_command.is_none()
            && !domain.skip_permissions_check,
        "dmux wez-first startup refused because the dmux unix domain does not match the broker's exact no-auto-start socket contract"
    );

    let attach_only = match invocation {
        ManagedGuiStartupInvocation::Connect {
            domain,
            new_tab,
            has_workspace,
            has_prog,
        } => domain == "dmux" && !new_tab && !has_workspace && !has_prog,
        ManagedGuiStartupInvocation::Start {
            domain,
            attach,
            always_new_process,
            new_tab,
            has_prog,
            has_cwd,
            has_workspace,
        } => {
            domain == Some("dmux")
                && attach
                && always_new_process
                && !new_tab
                && !has_prog
                && !has_cwd
                && !has_workspace
        }
        ManagedGuiStartupInvocation::NativeCreate => false,
    };
    anyhow::ensure!(
        attach_only,
        "dmux wez-first startup refused a native create path; use connect dmux or the frozen attach-only start command"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::keyassignment::{
        PaneDirection, PaneSelectArguments, RotationDirection, SpawnCommand, SpawnTabDomain,
        SplitPane, SplitSize,
    };
    use config::ConfigHandle;
    use config::UnixDomain;
    use std::path::PathBuf;

    fn retain_allowed(actions: &[KeyAssignment], dmux_managed_gui: bool) -> Vec<KeyAssignment> {
        actions
            .iter()
            .filter(|action| should_expose_ui_action(dmux_managed_gui, action))
            .cloned()
            .collect()
    }

    #[test]
    fn dmux_managed_gui_defaults_off() {
        assert!(!ConfigHandle::default_config().dmux_managed_gui);
    }

    #[test]
    fn action_filter_is_identity_when_disabled() {
        let actions = vec![
            KeyAssignment::SpawnWindow,
            KeyAssignment::SpawnTab(SpawnTabDomain::CurrentPaneDomain),
            KeyAssignment::AttachDomain("remote".to_string()),
            KeyAssignment::QuitApplication,
            KeyAssignment::CopyTo(config::keyassignment::ClipboardCopyDestination::Clipboard),
        ];

        assert_eq!(retain_allowed(&actions, false), actions);
    }

    #[test]
    fn action_filter_removes_managed_creation_and_lifecycle_bypasses() {
        let safe =
            KeyAssignment::CopyTo(config::keyassignment::ClipboardCopyDestination::Clipboard);
        let forbidden = vec![
            KeyAssignment::SpawnWindow,
            KeyAssignment::SpawnTab(SpawnTabDomain::CurrentPaneDomain),
            KeyAssignment::SpawnCommandInNewTab(SpawnCommand::default()),
            KeyAssignment::AttachDomain("remote".to_string()),
            KeyAssignment::SwitchToWorkspace {
                name: Some("existing-but-racy".to_string()),
                spawn: None,
            },
            KeyAssignment::SwitchWorkspaceRelative(1),
            KeyAssignment::MoveTab(0),
            KeyAssignment::MoveTabRelative(1),
            KeyAssignment::AdjustPaneSize(PaneDirection::Right, 3),
            KeyAssignment::TogglePaneZoomState,
            KeyAssignment::RotatePanes(RotationDirection::Clockwise),
            KeyAssignment::PaneSelect(PaneSelectArguments {
                mode: PaneSelectMode::SwapWithActive,
                ..PaneSelectArguments::default()
            }),
            KeyAssignment::CloseCurrentTab { confirm: true },
            KeyAssignment::HideApplication,
            KeyAssignment::QuitApplication,
            KeyAssignment::ReloadConfiguration,
        ];
        let mut actions = forbidden.clone();
        actions.push(safe.clone());

        assert_eq!(retain_allowed(&actions, true), vec![safe]);
        assert!(forbidden.iter().all(is_forbidden_ui_action));
    }

    #[test]
    fn nested_forbidden_action_is_removed() {
        let action = KeyAssignment::Multiple(vec![KeyAssignment::Nop, KeyAssignment::SpawnWindow]);
        assert!(is_forbidden_ui_action(&action));
    }

    #[test]
    fn close_request_policy_is_flag_gated() {
        assert_eq!(
            close_request_disposition(false),
            CloseRequestDisposition::FollowStandardPolicy
        );
        assert_eq!(
            close_request_disposition(true),
            CloseRequestDisposition::RefuseAndNotifyBroker
        );
    }

    #[test]
    fn runtime_barrier_blocks_direct_and_nested_bypasses_only_when_managed() {
        let forbidden = [
            KeyAssignment::SpawnWindow,
            KeyAssignment::SpawnTab(SpawnTabDomain::CurrentPaneDomain),
            KeyAssignment::SpawnCommandInNewTab(SpawnCommand::default()),
            KeyAssignment::SpawnCommandInNewWindow(SpawnCommand::default()),
            KeyAssignment::SplitHorizontal(SpawnCommand::default()),
            KeyAssignment::SplitVertical(SpawnCommand::default()),
            KeyAssignment::SplitPane(SplitPane {
                direction: PaneDirection::Right,
                size: SplitSize::Percent(50),
                command: SpawnCommand::default(),
                top_level: false,
            }),
            KeyAssignment::AttachDomain("dmux".to_string()),
            KeyAssignment::DetachDomain(SpawnTabDomain::CurrentPaneDomain),
            KeyAssignment::SwitchToWorkspace {
                name: Some("missing-can-create".to_string()),
                spawn: None,
            },
            KeyAssignment::SwitchWorkspaceRelative(1),
            KeyAssignment::MoveTab(0),
            KeyAssignment::MoveTabRelative(-1),
            KeyAssignment::AdjustPaneSize(PaneDirection::Left, 3),
            KeyAssignment::TogglePaneZoomState,
            KeyAssignment::SetPaneZoomState(true),
            KeyAssignment::RotatePanes(RotationDirection::CounterClockwise),
            KeyAssignment::PaneSelect(PaneSelectArguments {
                mode: PaneSelectMode::SwapWithActive,
                ..PaneSelectArguments::default()
            }),
            KeyAssignment::PaneSelect(PaneSelectArguments {
                mode: PaneSelectMode::SwapWithActiveKeepFocus,
                ..PaneSelectArguments::default()
            }),
            KeyAssignment::PaneSelect(PaneSelectArguments {
                mode: PaneSelectMode::MoveToNewTab,
                ..PaneSelectArguments::default()
            }),
            KeyAssignment::PaneSelect(PaneSelectArguments {
                mode: PaneSelectMode::MoveToNewWindow,
                ..PaneSelectArguments::default()
            }),
            KeyAssignment::CloseCurrentTab { confirm: false },
            KeyAssignment::CloseCurrentPane { confirm: false },
            KeyAssignment::HideApplication,
            KeyAssignment::QuitApplication,
            KeyAssignment::Multiple(vec![KeyAssignment::Nop, KeyAssignment::SpawnWindow]),
        ];

        for action in forbidden {
            assert!(should_perform_native_action(false, &action), "{:?}", action);
            assert!(!should_perform_native_action(true, &action), "{:?}", action);
        }
        let safe =
            KeyAssignment::CopyTo(config::keyassignment::ClipboardCopyDestination::Clipboard);
        assert!(should_perform_native_action(true, &safe));
    }

    #[test]
    fn runtime_barrier_preserves_focus_and_window_presentation_actions() {
        let allowed = [
            KeyAssignment::ActivateTab(0),
            KeyAssignment::ActivatePaneByIndex(0),
            KeyAssignment::ActivatePaneDirection(PaneDirection::Right),
            KeyAssignment::PaneSelect(PaneSelectArguments {
                mode: PaneSelectMode::Activate,
                ..PaneSelectArguments::default()
            }),
            KeyAssignment::Hide,
            KeyAssignment::Show,
            KeyAssignment::ToggleFullScreen,
        ];

        for action in allowed {
            assert!(should_perform_native_action(true, &action), "{:?}", action);
            assert!(should_expose_ui_action(true, &action), "{:?}", action);
        }
    }

    #[test]
    fn direct_mouse_tab_close_is_flag_gated() {
        assert!(should_close_tab_directly(false));
        assert!(!should_close_tab_directly(true));
        assert!(should_reload_gui_configuration(false));
        assert!(!should_reload_gui_configuration(true));
    }

    #[test]
    fn empty_managed_attach_cannot_fall_through_to_default_pane_spawn() {
        assert!(require_existing_panes_after_managed_attach(true, true, false).is_err());
        assert!(require_existing_panes_after_managed_attach(true, true, true).is_ok());
        assert!(require_existing_panes_after_managed_attach(false, true, false).is_ok());
        assert!(require_existing_panes_after_managed_attach(true, false, false).is_ok());
    }

    #[test]
    fn managed_safe_quit_api_is_narrow_and_default_off() {
        assert!(require_managed_safe_quit_api(false).is_err());
        assert!(require_managed_safe_quit_api(true).is_ok());
        assert!(require_managed_safe_hide_api(false).is_err());
        assert!(require_managed_safe_hide_api(true).is_ok());
        assert!(!should_perform_native_action(
            true,
            &KeyAssignment::QuitApplication
        ));
        assert!(!should_perform_native_action(
            true,
            &KeyAssignment::HideApplication
        ));
    }

    fn managed_domain(socket: &str) -> UnixDomain {
        UnixDomain {
            name: "dmux".to_string(),
            socket_path: Some(PathBuf::from(socket)),
            no_serve_automatically: true,
            ..UnixDomain::default()
        }
    }

    #[test]
    fn managed_config_errors_refuse_before_default_config_can_spawn() {
        for error in [
            "syntax error",
            "managed descriptor unavailable",
            "descriptor is not ready: starting",
        ] {
            assert!(require_successful_managed_config_load(true, Some(error)).is_err());
        }
        assert!(require_successful_managed_config_load(false, Some("syntax error")).is_ok());
        assert!(require_successful_managed_config_load(true, None).is_ok());
    }

    #[test]
    fn managed_startup_requires_exact_broker_attach_contract() {
        let args = vec!["connect".to_string(), "dmux".to_string()];
        let domains = vec![managed_domain("/run/user/1000/dmux/managed.sock")];
        let socket = OsStr::new("/run/user/1000/dmux/managed.sock");

        require_managed_startup_contract(
            true,
            true,
            &args,
            &domains,
            Some(socket),
            ManagedGuiStartupInvocation::Connect {
                domain: "dmux",
                new_tab: false,
                has_workspace: false,
                has_prog: false,
            },
        )
        .unwrap();
        require_managed_startup_contract(
            true,
            true,
            &args,
            &domains,
            Some(socket),
            ManagedGuiStartupInvocation::Start {
                domain: Some("dmux"),
                attach: true,
                always_new_process: true,
                new_tab: false,
                has_prog: false,
                has_cwd: false,
                has_workspace: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn managed_startup_refuses_direct_app_and_descriptor_bypasses() {
        let args = vec!["connect".to_string(), "dmux".to_string()];
        let domains = vec![managed_domain("/run/user/1000/dmux/managed.sock")];
        let socket = OsStr::new("/run/user/1000/dmux/managed.sock");

        for invocation in [
            ManagedGuiStartupInvocation::NativeCreate,
            ManagedGuiStartupInvocation::Start {
                domain: None,
                attach: false,
                always_new_process: false,
                new_tab: false,
                has_prog: false,
                has_cwd: false,
                has_workspace: false,
            },
        ] {
            assert!(require_managed_startup_contract(
                true,
                true,
                &args,
                &domains,
                Some(socket),
                invocation,
            )
            .is_err());
        }

        assert!(require_managed_startup_contract(
            true,
            true,
            &args,
            &domains,
            None,
            ManagedGuiStartupInvocation::Connect {
                domain: "dmux",
                new_tab: false,
                has_workspace: false,
                has_prog: false,
            },
        )
        .is_err());
        assert!(require_managed_startup_contract(
            true,
            true,
            &args,
            &domains,
            Some(OsStr::new("/tmp/wrong.sock")),
            ManagedGuiStartupInvocation::Connect {
                domain: "dmux",
                new_tab: false,
                has_workspace: false,
                has_prog: false,
            },
        )
        .is_err());

        // Environment/feature off is a semantic no-op, even for stock paths.
        require_managed_startup_contract(
            false,
            false,
            &[],
            &[],
            None,
            ManagedGuiStartupInvocation::NativeCreate,
        )
        .unwrap();
    }
}
