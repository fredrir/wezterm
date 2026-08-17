use clap::*;
use config::configuration;
use mux::activity::Activity;
use mux::domain::{Domain, LocalDomain};
use mux::Mux;
use portable_pty::cmdbuilder::CommandBuilder;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use wezterm_gui_subcommands::*;
use wezterm_mux_server_impl::{local::LocalListener, update_mux_domains_for_server};

mod daemonize;

#[derive(Debug, Parser)]
#[command(
    about = "Wez's Terminal Emulator\nhttp://github.com/wezterm/wezterm",
    version = config::wezterm_version(),
    trailing_var_arg = true,
)]
struct Opt {
    /// Skip loading wezterm.lua
    #[arg(long, short = 'n')]
    skip_config: bool,

    /// Specify the configuration file to use, overrides the normal
    /// configuration file resolution
    #[arg(
        long,
        value_parser,
        conflicts_with = "skip_config",
        value_hint=ValueHint::FilePath,
    )]
    config_file: Option<OsString>,

    /// Override specific configuration values
    #[arg(
        long = "config",
        name = "name=value",
        value_parser=clap::builder::ValueParser::new(name_equals_value),
        number_of_values = 1)]
    config_override: Vec<(String, String)>,

    /// Detach from the foreground and become a background process
    #[arg(long = "daemonize")]
    daemonize: bool,

    /// Prebind the fixed dmux service socket before configuration can start
    /// worker threads. This is an internal service-wrapper contract.
    #[arg(
        long = "dmux-managed-service",
        hide = true,
        requires = "config_file",
        conflicts_with_all = ["daemonize", "skip_config"]
    )]
    dmux_managed_service: bool,

    /// Specify the current working directory for the initially
    /// spawned program
    #[arg(long = "cwd", value_parser, value_hint=ValueHint::DirPath)]
    cwd: Option<OsString>,

    #[cfg(unix)]
    #[arg(long, hide = true)]
    pid_file_fd: Option<i32>,

    /// Instead of executing your shell, run PROG.
    /// For example: `wezterm start -- bash -l` will spawn bash
    /// as if it were a login shell.
    #[arg(value_parser, value_hint=ValueHint::CommandWithArguments, num_args=1..)]
    prog: Vec<OsString>,
}

fn main() {
    if let Err(err) = run() {
        wezterm_blob_leases::clear_storage();
        log::error!("{:#}", err);
        std::process::exit(1);
    }
    wezterm_blob_leases::clear_storage();
}

fn dmux_managed_service_flag_present(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != OsStr::new("--"))
        .any(|arg| arg.as_os_str() == OsStr::new("--dmux-managed-service"))
}

fn run() -> anyhow::Result<()> {
    let args = std::env::args_os().collect::<Vec<_>>();
    let managed_flag_present = dmux_managed_service_flag_present(&args);

    // On macOS, env_bootstrap initializes Foundation locale state, which can
    // start helper threads.  The managed socket bootstrap temporarily changes
    // cwd in order to bind relative to a held private-runtime dirfd, so its
    // single-thread assertion and prebind must happen before env_bootstrap.
    // Parse and validate the hidden service invocation first; ordinary mux
    // invocations retain their upstream bootstrap-before-parse ordering.
    if !managed_flag_present {
        env_bootstrap::bootstrap();
        config::designate_this_as_the_main_thread();
    }

    let opts = Opt::parse_from(args);

    if let Err(error) = validate_dmux_managed_invocation(&opts) {
        if managed_flag_present {
            eprintln!("dmux managed service invocation rejected: {error:#}");
        }
        return Err(error);
    }

    #[cfg(unix)]
    {
        // Ensure that we set CLOEXEC on the inherited lock file
        // before we have an opportunity to spawn any child processes.
        if let Some(fd) = opts.pid_file_fd {
            daemonize::set_cloexec(fd, true);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let dmux_service_bootstrap = if opts.dmux_managed_service {
        Some(
            mux_lua::dmux_descriptor::prebind_dmux_managed_service().map_err(|error| {
                eprintln!("dmux managed service prebind failed: {error:#}");
                error
            })?,
        )
    } else {
        None
    };

    if managed_flag_present {
        env_bootstrap::bootstrap();
        config::designate_this_as_the_main_thread();
    }

    //stats::Stats::init()?;
    let _saver = umask::UmaskSaver::new();

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    anyhow::ensure!(
        !opts.dmux_managed_service,
        "--dmux-managed-service is supported only on Linux and macOS"
    );

    config::common_init(
        opts.config_file.as_ref(),
        &opts.config_override,
        opts.skip_config,
    )?;

    let config = config::configuration();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let (dmux_listener, _dmux_service_guard) = match dmux_service_bootstrap {
        Some(bootstrap) => {
            let (listener, guard) = bootstrap.validate_and_take(&config)?;
            (Some(LocalListener::new(listener)), Some(guard))
        }
        None => {
            anyhow::ensure!(
                !mux_lua::dmux_descriptor::service_bootstrap_missing_prebind_attempted(),
                "managed mux configuration attempted bootstrap without --dmux-managed-service"
            );
            (None, None)
        }
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let dmux_listener: Option<LocalListener> = None;

    config.update_ulimit()?;
    if let Some(value) = &config.default_ssh_auth_sock {
        std::env::set_var("SSH_AUTH_SOCK", value);
    }

    #[cfg(unix)]
    let mut pid_file = None;

    #[cfg(unix)]
    {
        if opts.daemonize {
            pid_file = daemonize::daemonize(&config)?;
            // When we reach this line, we are in a forked child process,
            // and the fork will have broken the async-io/reactor state
            // of the smol runtime.
            // To resolve this, we will re-exec ourselves in the block
            // below that was originally Windows-specific
        }
    }

    if opts.daemonize {
        // On Windows we can't literally daemonize, but we can spawn another copy
        // of ourselves in the background!
        // On Unix, forking breaks the global state maintained by `smol`,
        // so we need to re-exec ourselves to start things back up properly.
        let mut cmd = Command::new(std::env::current_exe().unwrap());

        #[cfg(unix)]
        {
            // Inform the new version of ourselves that we already
            // locked the pidfile so that it can prevent it from
            // being propagated to its children when they spawn
            if let Some(fd) = pid_file {
                cmd.arg("--pid-file-fd");
                cmd.arg(&fd.to_string());
            }
        }
        if opts.skip_config {
            cmd.arg("-n");
        }
        if let Some(f) = &opts.config_file {
            cmd.arg("--config-file");
            cmd.arg(f);
        }
        for (name, value) in &opts.config_override {
            cmd.arg("--config");
            cmd.arg(&format!("{name}={value}"));
        }
        if let Some(cwd) = opts.cwd {
            cmd.arg("--cwd");
            cmd.arg(cwd);
        }
        if !opts.prog.is_empty() {
            cmd.arg("--");
            for a in &opts.prog {
                cmd.arg(a);
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.stdout(config.daemon_options.open_stdout()?);
            cmd.stderr(config.daemon_options.open_stderr()?);

            cmd.creation_flags(winapi::um::winbase::DETACHED_PROCESS);
            let child = cmd.spawn();
            drop(child);
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if let Some(mask) = umask::UmaskSaver::saved_umask() {
                unsafe {
                    cmd.pre_exec(move || {
                        libc::umask(mask);
                        Ok(())
                    });
                }
            }

            return Err(anyhow::anyhow!("failed to re-exec: {:?}", cmd.exec()));
        }
    }

    // Remove some environment variables that aren't super helpful or
    // that are potentially misleading when we're starting up the
    // server.
    // We may potentially want to look into starting/registering
    // a session of some kind here as well in the future.
    for name in &[
        "OLDPWD",
        "PWD",
        "SHLVL",
        "WEZTERM_PANE",
        "WEZTERM_UNIX_SOCKET",
        "_",
    ] {
        std::env::remove_var(name);
    }
    for name in &config::configuration().mux_env_remove {
        std::env::remove_var(name);
    }

    wezterm_blob_leases::register_storage(Arc::new(
        wezterm_blob_leases::simple_tempdir::SimpleTempDir::new_in(&*config::CACHE_DIR)?,
    ))?;

    let need_builder = !opts.prog.is_empty() || opts.cwd.is_some();

    let cmd = if need_builder {
        let mut builder = if opts.prog.is_empty() {
            CommandBuilder::new_default_prog()
        } else {
            CommandBuilder::from_argv(opts.prog)
        };
        if let Some(cwd) = opts.cwd {
            builder.cwd(cwd);
        }
        Some(builder)
    } else {
        None
    };

    let domain: Arc<dyn Domain> = Arc::new(LocalDomain::new("local")?);
    let mux = Arc::new(mux::Mux::new(Some(domain.clone())));
    Mux::set_mux(&mux);

    let executor = promise::spawn::SimpleExecutor::new();

    spawn_listener(dmux_listener).map_err(|e| {
        log::error!("problem spawning listeners: {:?}", e);
        e
    })?;

    let activity = Activity::new();

    let dmux_managed_service = opts.dmux_managed_service;
    promise::spawn::spawn(async move {
        if let Err(err) = async_run(cmd, dmux_managed_service).await {
            terminate_with_error(err);
        }
        drop(activity);
    })
    .detach();

    loop {
        executor.tick()?;
    }
}

fn validate_dmux_managed_invocation(opts: &Opt) -> anyhow::Result<()> {
    if !opts.dmux_managed_service {
        return Ok(());
    }
    anyhow::ensure!(
        opts.config_override.is_empty() && opts.cwd.is_none() && opts.prog.is_empty(),
        "--dmux-managed-service accepts only the fixed --config-file invocation"
    );
    let config_file = opts
        .config_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--dmux-managed-service requires --config-file"))?;
    anyhow::ensure!(
        Path::new(config_file).is_absolute(),
        "--dmux-managed-service requires an absolute --config-file"
    );
    #[cfg(unix)]
    anyhow::ensure!(
        opts.pid_file_fd.is_none(),
        "--dmux-managed-service refuses inherited daemon pid-file descriptors"
    );
    Ok(())
}

async fn trigger_mux_startup(lua: Option<Rc<mlua::Lua>>) -> anyhow::Result<()> {
    if let Some(lua) = lua {
        let args = lua.pack_multi(())?;
        config::lua::emit_event(&lua, ("mux-startup".to_string(), args)).await?;
    }
    Ok(())
}

async fn async_run(cmd: Option<CommandBuilder>, dmux_managed_service: bool) -> anyhow::Result<()> {
    let mux = Mux::get();
    let config = config::configuration();

    update_mux_domains_for_server(&config)?;
    let _config_subscription = config::subscribe_to_config_reload(move || {
        promise::spawn::spawn_into_main_thread(async move {
            if let Err(err) = update_mux_domains_for_server(&config::configuration()) {
                log::error!("Error updating mux domains: {:#}", err);
            }
        })
        .detach();
        true
    });

    let domain = mux.default_domain();

    {
        if let Err(err) = config::with_lua_config_on_main_thread(trigger_mux_startup).await {
            log::error!("while processing mux-startup event: {:#}", err);
        }
    }

    let have_panes_in_domain = mux
        .iter_panes()
        .iter()
        .any(|p| p.domain_id() == domain.domain_id());

    if should_spawn_default_pane(dmux_managed_service, have_panes_in_domain)? {
        let workspace = None;
        let position = None;
        let window_id = mux.new_empty_window(workspace, position);
        domain.attach(Some(*window_id)).await?;

        let _tab = mux
            .default_domain()
            .spawn(config.initial_size(0, None), cmd, None, *window_id)
            .await?;
    }
    Ok(())
}

fn should_spawn_default_pane(
    dmux_managed_service: bool,
    have_panes_in_domain: bool,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        !dmux_managed_service || have_panes_in_domain,
        "dmux managed mux-startup produced no sentinel/user pane; refusing default-pane fallback"
    );
    Ok(!have_panes_in_domain)
}

fn terminate_with_error(err: anyhow::Error) -> ! {
    log::error!("{:#}; terminating", err);
    std::process::exit(1);
}

mod ossl;

pub fn spawn_listener(managed_listener: Option<LocalListener>) -> anyhow::Result<()> {
    let config = configuration();
    if let Some(mut listener) = managed_listener {
        let unix_dom = config.unix_domains.first().ok_or_else(|| {
            anyhow::anyhow!("managed listener handoff has no configured Unix domain")
        })?;
        std::env::set_var("WEZTERM_UNIX_SOCKET", unix_dom.socket_path());
        thread::spawn(move || {
            listener.run();
        });
    } else {
        for unix_dom in &config.unix_domains {
            std::env::set_var("WEZTERM_UNIX_SOCKET", unix_dom.socket_path());
            let mut listener = LocalListener::with_domain(unix_dom)?;
            thread::spawn(move || {
                listener.run();
            });
        }
    }

    for tls_server in &config.tls_servers {
        ossl::spawn_tls_listener(tls_server)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Opt, clap::Error> {
        Opt::try_parse_from(std::iter::once("wezterm-mux-server").chain(args.iter().copied()))
    }

    #[test]
    fn managed_service_flag_is_detected_for_early_prebind_only() {
        let args = IntoIterator::into_iter([
            "wezterm-mux-server",
            "--dmux-managed-service",
            "--config-file",
            "/tmp/dmux-mux.lua",
        ])
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert!(dmux_managed_service_flag_present(&args));

        let program_args =
            IntoIterator::into_iter(["wezterm-mux-server", "--", "sh", "--dmux-managed-service"])
                .map(OsString::from)
                .collect::<Vec<_>>();
        assert!(!dmux_managed_service_flag_present(&program_args));
    }

    #[test]
    fn managed_service_flag_requires_exact_foreground_config_invocation() {
        assert!(parse(&["--dmux-managed-service"]).is_err());
        assert!(parse(&[
            "--dmux-managed-service",
            "--config-file",
            "/tmp/dmux-mux.lua",
            "--daemonize",
        ])
        .is_err());
        assert!(parse(&[
            "--dmux-managed-service",
            "--config-file",
            "/tmp/dmux-mux.lua",
            "-n",
        ])
        .is_err());

        let exact = parse(&[
            "--dmux-managed-service",
            "--config-file",
            "/tmp/dmux-mux.lua",
        ])
        .unwrap();
        validate_dmux_managed_invocation(&exact).unwrap();

        for extra in [
            vec!["--cwd", "/tmp"],
            vec!["--config", "font_size=10"],
            vec!["--", "sh"],
        ] {
            let mut args = vec![
                "--dmux-managed-service",
                "--config-file",
                "/tmp/dmux-mux.lua",
            ];
            args.extend(extra);
            let parsed = parse(&args).unwrap();
            assert!(validate_dmux_managed_invocation(&parsed).is_err());
        }

        let relative = parse(&["--dmux-managed-service", "--config-file", "dmux-mux.lua"]).unwrap();
        assert!(validate_dmux_managed_invocation(&relative).is_err());
    }

    #[test]
    fn ordinary_mux_invocation_remains_unchanged() {
        let ordinary = parse(&["--config-file", "wezterm.lua", "--", "sh"])
            .expect("ordinary legacy invocation parses");
        validate_dmux_managed_invocation(&ordinary).unwrap();
    }

    #[test]
    fn managed_mux_never_falls_through_to_the_default_program() {
        assert_eq!(should_spawn_default_pane(false, false).unwrap(), true);
        assert_eq!(should_spawn_default_pane(false, true).unwrap(), false);
        assert_eq!(should_spawn_default_pane(true, true).unwrap(), false);
        assert!(should_spawn_default_pane(true, false).is_err());
    }
}
