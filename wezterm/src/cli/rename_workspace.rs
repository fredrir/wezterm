use clap::Parser;
use mux::pane::PaneId;
use std::collections::HashMap;
use wezterm_client::client::Client;

#[derive(Debug, Parser, Clone)]
pub struct RenameWorkspace {
    /// Specify the workspace to rename
    #[arg(long)]
    workspace: Option<String>,

    /// Specify the current pane.
    /// The default is to use the current pane based on the
    /// environment variable WEZTERM_PANE.
    ///
    /// The pane is used to figure out which workspace
    /// should be renamed.
    #[arg(long)]
    pane_id: Option<PaneId>,

    /// Conditionally rename the workspace of just this window,
    /// atomically on the server, and only if its current workspace
    /// matches --if-workspace at execution time.
    /// Requires --if-workspace.
    #[arg(long, requires = "if_workspace", conflicts_with_all = ["workspace", "pane_id"])]
    window_id: Option<mux::window::WindowId>,

    /// The workspace the window identified by --window-id is expected
    /// to be in. If the window is in a different workspace at the time
    /// the server executes the request, nothing is renamed and the
    /// command fails with a workspace_mismatch error.
    #[arg(long, requires = "window_id")]
    if_workspace: Option<String>,

    /// Additionally require that --window-id is the only window in the
    /// expected workspace at execution time.
    #[arg(long, requires = "window_id")]
    if_sole_window: bool,

    /// The new name for the workspace
    new_workspace: String,
}

impl RenameWorkspace {
    pub async fn run(self, client: Client) -> anyhow::Result<()> {
        if let Some(window_id) = self.window_id {
            let expected_workspace = self
                .if_workspace
                .clone()
                .expect("clap enforces that --window-id requires --if-workspace");
            let response = client
                .rename_workspace_if(codec::RenameWorkspaceIf {
                    window_id,
                    expected_workspace,
                    new_workspace: self.new_workspace,
                    expect_sole_window: self.if_sole_window,
                })
                .await?;
            use codec::RenameWorkspaceCasOutcome as Outcome;
            return match response.outcome {
                Outcome::Renamed => Ok(()),
                Outcome::NoSuchWindow => anyhow::bail!(
                    "rename-workspace-if failed: no_such_window window_id={window_id}"
                ),
                Outcome::WorkspaceMismatch { actual } => anyhow::bail!(
                    "rename-workspace-if failed: workspace_mismatch \
                     window_id={window_id} actual={actual:?}"
                ),
                Outcome::NotSoleWindow { other_window_ids } => anyhow::bail!(
                    "rename-workspace-if failed: not_sole_window \
                     window_id={window_id} other_window_ids={other_window_ids:?}"
                ),
            };
        }

        let panes = client.list_panes().await?;

        let mut pane_id_to_workspace = HashMap::new();

        for tabroot in panes.tabs {
            let mut cursor = tabroot.into_tree().cursor();

            loop {
                if let Some(entry) = cursor.leaf_mut() {
                    pane_id_to_workspace.insert(entry.pane_id, entry.workspace.to_string());
                }
                match cursor.preorder_next() {
                    Ok(c) => cursor = c,
                    Err(_) => break,
                }
            }
        }

        let old_workspace = if let Some(workspace) = self.workspace {
            workspace
        } else {
            // Find the current tab from the pane id
            let pane_id = client.resolve_pane_id(self.pane_id).await?;
            pane_id_to_workspace
                .get(&pane_id)
                .ok_or_else(|| anyhow::anyhow!("unable to resolve current workspace"))?
                .to_string()
        };

        client
            .rename_workspace(codec::RenameWorkspace {
                old_workspace,
                new_workspace: self.new_workspace,
            })
            .await?;
        Ok(())
    }
}
