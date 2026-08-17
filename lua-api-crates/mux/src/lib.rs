use config::keyassignment::SpawnTabDomain;
use config::lua::mlua::{self, Lua, Table, UserData, UserDataMethods, Value as LuaValue};
use config::lua::{get_or_create_module, get_or_create_sub_module};
use luahelper::impl_lua_conversion_dynamic;
use luahelper::mlua::LuaSerdeExt;
use mlua::UserDataRef;
use mux::domain::{DomainId, SplitSource};
use mux::pane::{Pane, PaneId};
use mux::tab::{SplitDirection, SplitRequest, SplitSize, Tab, TabId};
use mux::window::{Window, WindowId};
use mux::{Mux, RecoveryRemoveOutcome, RecoveryRemoveStatus, RecoveryRemoveTarget};
use portable_pty::CommandBuilder;
use std::collections::HashMap;
use std::sync::Arc;
use wezterm_dynamic::{FromDynamic, ToDynamic};
use wezterm_term::TerminalSize;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod dmux_descriptor;
mod domain;
mod pane;
mod tab;
mod window;

pub use domain::MuxDomain;
pub use pane::MuxPane;
pub use tab::MuxTab;
pub use window::MuxWindow;

fn get_mux() -> mlua::Result<Arc<Mux>> {
    Mux::try_get().ok_or_else(|| mlua::Error::external("cannot get Mux!?"))
}

pub fn register(lua: &Lua) -> anyhow::Result<()> {
    let mux_mod = get_or_create_sub_module(lua, "mux")?;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    dmux_descriptor::register(lua, &mux_mod)?;

    mux_mod.set(
        "get_active_workspace",
        lua.create_function(|_, _: ()| {
            let mux = get_mux()?;
            Ok(mux.active_workspace())
        })?,
    )?;

    mux_mod.set(
        "get_workspace_names",
        lua.create_function(|_, _: ()| {
            let mux = get_mux()?;
            Ok(mux.iter_workspaces())
        })?,
    )?;

    mux_mod.set(
        "set_active_workspace",
        lua.create_function(|_, workspace: String| {
            let mux = get_mux()?;
            let workspaces = mux.iter_workspaces();
            if workspaces.contains(&workspace) {
                Ok(mux.set_active_workspace(&workspace))
            } else {
                Err(mlua::Error::external(format!(
                    "{:?} is not an existing workspace",
                    workspace
                )))
            }
        })?,
    )?;

    mux_mod.set(
        "rename_workspace",
        lua.create_function(|_, (old_workspace, new_workspace): (String, String)| {
            let mux = get_mux()?;
            mux.rename_workspace(&old_workspace, &new_workspace);
            Ok(())
        })?,
    )?;

    mux_mod.set(
        "get_window",
        lua.create_function(|_, window_id: WindowId| {
            let mux = get_mux()?;
            let window = MuxWindow(window_id);
            let _resolved = window.resolve(&mux)?;
            Ok(window)
        })?,
    )?;

    mux_mod.set(
        "get_pane",
        lua.create_function(|_, pane_id: PaneId| {
            let mux = get_mux()?;
            let pane = MuxPane(pane_id);
            pane.resolve(&mux)?;
            Ok(pane)
        })?,
    )?;

    mux_mod.set(
        "get_tab",
        lua.create_function(|_, tab_id: TabId| {
            let mux = get_mux()?;
            let tab = MuxTab(tab_id);
            tab.resolve(&mux)?;
            Ok(tab)
        })?,
    )?;

    mux_mod.set(
        "spawn_window",
        lua.create_async_function(|_, spawn: SpawnWindow| async move { spawn.spawn().await })?,
    )?;

    mux_mod.set(
        "all_windows",
        lua.create_function(|_, _: ()| {
            let mux = get_mux()?;
            Ok(mux
                .iter_windows()
                .into_iter()
                .map(MuxWindow)
                .collect::<Vec<MuxWindow>>())
        })?,
    )?;

    mux_mod.set(
        "get_domain",
        lua.create_function(|_, domain: LuaValue| {
            let mux = get_mux()?;
            match domain {
                LuaValue::Nil => Ok(Some(MuxDomain(mux.default_domain().domain_id()))),
                LuaValue::String(s) => match s.to_str() {
                    Ok(name) => Ok(mux
                        .get_domain_by_name(name)
                        .map(|dom| MuxDomain(dom.domain_id()))),
                    Err(err) => Err(mlua::Error::external(format!(
                        "invalid domain identifier passed to mux.get_domain: {err:#}"
                    ))),
                },
                LuaValue::Integer(id) => match TryInto::<DomainId>::try_into(id) {
                    Ok(id) => Ok(mux.get_domain(id).map(|dom| MuxDomain(dom.domain_id()))),
                    Err(err) => Err(mlua::Error::external(format!(
                        "invalid domain identifier passed to mux.get_domain: {err:#}"
                    ))),
                },
                _ => Err(mlua::Error::external(
                    "invalid domain identifier passed to mux.get_domain".to_string(),
                )),
            }
        })?,
    )?;

    mux_mod.set(
        "all_domains",
        lua.create_function(|_, _: ()| {
            let mux = get_mux()?;
            Ok(mux
                .iter_domains()
                .into_iter()
                .map(|dom| MuxDomain(dom.domain_id()))
                .collect::<Vec<MuxDomain>>())
        })?,
    )?;

    mux_mod.set(
        "set_default_domain",
        lua.create_function(|_, domain: UserDataRef<MuxDomain>| {
            let mux = get_mux()?;
            let domain = domain.resolve(&mux)?;
            mux.set_default_domain(&domain);
            Ok(())
        })?,
    )?;

    mux_mod.set(
        "dmux_recovery_remove_node",
        lua.create_function(|lua, request: Table| {
            let target = parse_recovery_remove_target(request)?;
            let outcome = if config::configuration().dmux_recovery_primitives {
                let mux = get_mux()?;
                mux.remove_recovery_node_exact(target)
            } else {
                let mut outcome = RecoveryRemoveOutcome::new(target.kind(), target.native_id());
                outcome.status = RecoveryRemoveStatus::Disabled;
                outcome
            };
            lua.to_value(&outcome)
        })?,
    )?;

    Ok(())
}

fn parse_recovery_remove_target(request: Table) -> mlua::Result<RecoveryRemoveTarget> {
    let kind: String = request.raw_get("kind")?;
    let allowed_fields: &[&str] = match kind.as_str() {
        "pane" => &["kind", "native_id", "parent_tab_id", "parent_window_id"],
        "tab" => &["kind", "native_id", "parent_window_id"],
        "window" => &["kind", "native_id", "workspace"],
        _ => {
            return Err(mlua::Error::external(format!(
                "invalid dmux recovery node kind {kind:?}; expected pane, tab, or window"
            )))
        }
    };

    for pair in request.clone().pairs::<LuaValue, LuaValue>() {
        let (key, _value) = pair?;
        let key = match key {
            LuaValue::String(key) => key.to_str()?.to_string(),
            other => {
                return Err(mlua::Error::external(format!(
                    "dmux recovery request keys must be strings, got {}",
                    other.type_name()
                )))
            }
        };
        if !allowed_fields.contains(&key.as_str()) {
            return Err(mlua::Error::external(format!(
                "unknown field {key:?} for dmux recovery {kind} request"
            )));
        }
    }

    let native_id: usize = request.raw_get("native_id")?;
    match kind.as_str() {
        "pane" => Ok(RecoveryRemoveTarget::Pane {
            pane_id: native_id,
            parent_tab_id: request.raw_get("parent_tab_id")?,
            parent_window_id: request.raw_get("parent_window_id")?,
        }),
        "tab" => Ok(RecoveryRemoveTarget::Tab {
            tab_id: native_id,
            parent_window_id: request.raw_get("parent_window_id")?,
        }),
        "window" => {
            let workspace: String = request.raw_get("workspace")?;
            if workspace.is_empty() {
                return Err(mlua::Error::external(
                    "dmux recovery window workspace must not be empty",
                ));
            }
            Ok(RecoveryRemoveTarget::Window {
                window_id: native_id,
                workspace,
            })
        }
        _ => unreachable!(),
    }
}

#[derive(Debug, Default, FromDynamic, ToDynamic)]
struct CommandBuilderFrag {
    args: Option<Vec<String>>,
    cwd: Option<String>,
    #[dynamic(default)]
    set_environment_variables: HashMap<String, String>,
}

impl CommandBuilderFrag {
    fn to_command_builder(&self) -> (Option<CommandBuilder>, Option<String>) {
        if let Some(args) = &self.args {
            let mut builder = CommandBuilder::from_argv(args.iter().map(Into::into).collect());
            for (k, v) in self.set_environment_variables.iter() {
                builder.env(k, v);
            }
            if let Some(cwd) = self.cwd.clone() {
                builder.cwd(cwd);
            }
            (Some(builder), None)
        } else {
            (None, self.cwd.clone())
        }
    }
}

#[derive(Debug, FromDynamic, ToDynamic)]
enum HandySplitDirection {
    Left,
    Right,
    Top,
    Bottom,
}
impl_lua_conversion_dynamic!(HandySplitDirection);

impl Default for HandySplitDirection {
    fn default() -> Self {
        Self::Right
    }
}

#[derive(Debug, FromDynamic, ToDynamic)]
struct SpawnWindow {
    #[dynamic(default = "spawn_tab_default_domain")]
    domain: SpawnTabDomain,
    width: Option<usize>,
    height: Option<usize>,
    workspace: Option<String>,
    position: Option<config::GuiPosition>,
    #[dynamic(flatten)]
    cmd_builder: CommandBuilderFrag,
}
impl_lua_conversion_dynamic!(SpawnWindow);

fn spawn_tab_default_domain() -> SpawnTabDomain {
    SpawnTabDomain::DefaultDomain
}

impl SpawnWindow {
    async fn spawn(self) -> mlua::Result<(MuxTab, MuxPane, MuxWindow)> {
        let mux = get_mux()?;

        let size = match (self.width, self.height) {
            (Some(cols), Some(rows)) => TerminalSize {
                rows,
                cols,
                ..Default::default()
            },
            _ => config::configuration().initial_size(0, None),
        };

        let (cmd_builder, cwd) = self.cmd_builder.to_command_builder();
        let (tab, pane, window_id) = mux
            .spawn_tab_or_window(
                None,
                self.domain,
                cmd_builder,
                cwd,
                size,
                None,
                self.workspace.unwrap_or_else(|| mux.active_workspace()),
                self.position,
            )
            .await
            .map_err(|e| mlua::Error::external(format!("{:#?}", e)))?;

        Ok((
            MuxTab(tab.tab_id()),
            MuxPane(pane.pane_id()),
            MuxWindow(window_id),
        ))
    }
}

#[derive(Debug, FromDynamic, ToDynamic)]
struct SpawnTab {
    #[dynamic(default)]
    domain: SpawnTabDomain,
    #[dynamic(flatten)]
    cmd_builder: CommandBuilderFrag,
}
impl_lua_conversion_dynamic!(SpawnTab);

impl SpawnTab {
    async fn spawn(self, window: &MuxWindow) -> mlua::Result<(MuxTab, MuxPane, MuxWindow)> {
        let mux = get_mux()?;
        let size;
        let pane;

        {
            let window = window.resolve(&mux)?;
            size = window
                .get_by_idx(0)
                .map(|tab| tab.get_size())
                .unwrap_or_else(|| config::configuration().initial_size(0, None));

            pane = window
                .get_active()
                .and_then(|tab| tab.get_active_pane().map(|pane| pane.pane_id()));
        };

        let (cmd_builder, cwd) = self.cmd_builder.to_command_builder();

        let (tab, pane, window_id) = mux
            .spawn_tab_or_window(
                Some(window.0),
                self.domain,
                cmd_builder,
                cwd,
                size,
                pane,
                String::new(),
                None, // optional gui window position
            )
            .await
            .map_err(|e| mlua::Error::external(format!("{:#?}", e)))?;

        Ok((
            MuxTab(tab.tab_id()),
            MuxPane(pane.pane_id()),
            MuxWindow(window_id),
        ))
    }
}

#[derive(Clone, FromDynamic, ToDynamic)]
struct MuxTabInfo {
    pub index: usize,
    pub is_active: bool,
}
impl_lua_conversion_dynamic!(MuxTabInfo);

#[derive(Clone, FromDynamic, ToDynamic)]
struct MuxPaneInfo {
    /// The topological pane index that can be used to reference this pane
    pub index: usize,
    /// true if this is the active pane at the time the position was computed
    pub is_active: bool,
    /// true if this pane is zoomed
    pub is_zoomed: bool,
    /// The offset from the top left corner of the containing tab to the top
    /// left corner of this pane, in cells.
    pub left: usize,
    /// The offset from the top left corner of the containing tab to the top
    /// left corner of this pane, in cells.
    pub top: usize,
    /// The width of this pane in cells
    pub width: usize,
    pub pixel_width: usize,
    /// The height of this pane in cells
    pub height: usize,
    pub pixel_height: usize,
}
impl_lua_conversion_dynamic!(MuxPaneInfo);

#[cfg(test)]
mod recovery_remove_lua_tests {
    use super::*;

    fn install_config(enabled: bool) {
        let mut config = config::Config::default();
        config.mux_enable_ssh_agent = false;
        config.dmux_recovery_primitives = enabled;
        config::use_this_configuration(config);
    }

    fn add_empty_window(mux: &Mux, workspace: &str) -> WindowId {
        let builder = mux.new_empty_window(Some(workspace.to_string()), None);
        let window_id = *builder;
        drop(builder);
        window_id
    }

    #[test]
    fn lua_gate_closed_schema_and_typed_window_outcomes() {
        assert!(!config::Config::default().dmux_recovery_primitives);
        let executor = promise::spawn::SimpleExecutor::new();
        install_config(false);
        let mux = Arc::new(Mux::new(None));
        Mux::set_mux(&mux);
        let lua = Lua::new();
        register(&lua).unwrap();
        lua.load("wezterm = require 'wezterm'").exec().unwrap();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let (publisher, spool_open, manifest_open): (String, String, String) = lua
                .load(
                    "return type(wezterm.mux.dmux_publish_service_descriptor), \
                            type(wezterm.mux.dmux_recovery_spool_open), \
                            type(wezterm.mux.dmux_recovery_manifest_open)",
                )
                .eval()
                .unwrap();
            assert_eq!(publisher, "function");
            assert_eq!(spool_open, "function");
            assert_eq!(manifest_open, "function");
            let error: String = lua
                .load(
                    "local ok, err = pcall(wezterm.mux.dmux_recovery_spool_open, \
                         '11111111-1111-4111-8111-111111111111'); \
                     assert(not ok); return tostring(err)",
                )
                .eval()
                .unwrap();
            assert!(error.contains("dmux_recovery_spool_disabled"), "{error:#}");
        }

        let (status, kind, requested_native_id, pane_count, tab_count, window_count): (
            String,
            String,
            usize,
            usize,
            usize,
            usize,
        ) = lua
            .load(
                r#"
                local result = wezterm.mux.dmux_recovery_remove_node {
                  kind = 'window',
                  native_id = 71,
                  workspace = 'dmux:space:disabled',
                }
                return result.status, result.kind, result.requested_native_id,
                       #result.removed_pane_ids, #result.removed_tab_ids,
                       #result.removed_window_ids
                "#,
            )
            .eval()
            .unwrap();
        assert_eq!(status, "disabled");
        assert_eq!(kind, "window");
        assert_eq!(requested_native_id, 71);
        assert_eq!((pane_count, tab_count, window_count), (0, 0, 0));

        for forbidden_field in ["pid", "command", "workspace_ordinal"] {
            let script = format!(
                r#"
                return wezterm.mux.dmux_recovery_remove_node {{
                  kind = 'window', native_id = 71,
                  workspace = 'dmux:space:closed-schema',
                  {forbidden_field} = 'forbidden',
                }}
                "#
            );
            let error = lua.load(&script).eval::<LuaValue>().unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "unexpected error for {forbidden_field}: {error:#}"
            );
        }

        install_config(true);
        for (request, expected_kind) in [
            (
                "{kind='pane', native_id=9001, parent_tab_id=9002, parent_window_id=9003}",
                "pane",
            ),
            ("{kind='tab', native_id=9011, parent_window_id=9012}", "tab"),
        ] {
            let script = format!(
                "local result = wezterm.mux.dmux_recovery_remove_node {request}; \
                 return result.status, result.kind, #result.removed_pane_ids, \
                 #result.removed_tab_ids, #result.removed_window_ids"
            );
            let (status, kind, panes, tabs, windows): (String, String, usize, usize, usize) =
                lua.load(&script).eval().unwrap();
            assert_eq!(status, "not_found");
            assert_eq!(kind, expected_kind);
            assert_eq!((panes, tabs, windows), (0, 0, 0));
        }

        let window_id = add_empty_window(&mux, "dmux:space:lua-exact");

        let mismatch_script = format!(
            r#"
            local result = wezterm.mux.dmux_recovery_remove_node {{
              kind = 'window', native_id = {window_id},
              workspace = 'dmux:space:wrong-parent',
            }}
            return result.status, #result.removed_window_ids
            "#
        );
        let (status, removed_count): (String, usize) = lua.load(&mismatch_script).eval().unwrap();
        assert_eq!(status, "parent_mismatch");
        assert_eq!(removed_count, 0);
        assert!(mux.get_window(window_id).is_some());

        let remove_script = format!(
            r#"
            local result = wezterm.mux.dmux_recovery_remove_node {{
              kind = 'window', native_id = {window_id},
              workspace = 'dmux:space:lua-exact',
            }}
            return result.status, result.kind, result.requested_native_id,
                   #result.removed_pane_ids, #result.removed_tab_ids,
                   result.removed_window_ids[1]
            "#
        );
        let (status, kind, requested, pane_count, tab_count, removed_window): (
            String,
            String,
            usize,
            usize,
            usize,
            usize,
        ) = lua.load(&remove_script).eval().unwrap();
        assert_eq!(status, "removed");
        assert_eq!(kind, "window");
        assert_eq!(requested, window_id);
        assert_eq!((pane_count, tab_count), (0, 0));
        assert_eq!(removed_window, window_id);
        assert!(mux.get_window(window_id).is_none());

        let (status, pane_count, tab_count, window_count): (String, usize, usize, usize) = lua
            .load(&remove_script)
            .eval::<(String, String, usize, usize, usize, Option<usize>)>()
            .map(|(status, _, _, pane_count, tab_count, removed_window)| {
                (
                    status,
                    pane_count,
                    tab_count,
                    usize::from(removed_window.is_some()),
                )
            })
            .unwrap();
        assert_eq!(status, "not_found");
        assert_eq!((pane_count, tab_count, window_count), (0, 0, 0));
        executor.tick().unwrap();
    }
}
