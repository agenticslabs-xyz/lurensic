//! kagami-enforcer, the command line program. See `kagami-enforcer help`.

use kagami_enforcer::blocklist;
use kagami_enforcer::cloudflare::{self, Client};
use kagami_enforcer::http::Ureq;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HELP: &str = "kagami-enforcer pushes machines that Kagami has contained to an edge firewall.

Usage
  kagami-enforcer cloudflare setup  [--name kagami_contained]
  kagami-enforcer cloudflare sync   --from <contained.json> [--watch <seconds>] [--id <name>]
  kagami-enforcer cloudflare status
  kagami-enforcer version

The blocklist file is the JSON file a Kagami adapter writes, for example
blocklistFile({ path: 'contained.json', format: 'json' }) in Node.

Settings come from the environment, or from the matching flag.
  CLOUDFLARE_API_TOKEN       API token with the account permission \"Account Filter Lists Edit\" (environment only)
  CLOUDFLARE_ACCOUNT_ID      --account
  KAGAMI_CLOUDFLARE_LIST_ID  --list
  KAGAMI_BLOCKLIST           --from
  KAGAMI_ENFORCER_ID         --id     names this enforcer when several share one list (default \"default\")
";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
}

impl Args {
    fn parse() -> Result<Args, String> {
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                if name == "help" {
                    positional.insert(0, "help".into());
                    continue;
                }
                let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                flags.push((name.to_string(), value));
            } else {
                positional.push(a);
            }
        }
        Ok(Args { positional, flags })
    }

    /// A flag, else an environment variable.
    fn get(&self, flag: &str, env: &str) -> Option<String> {
        self.flags
            .iter()
            .rev()
            .find(|(k, _)| k == flag)
            .map(|(_, v)| v.clone())
            .or_else(|| std::env::var(env).ok())
            .filter(|v| !v.trim().is_empty())
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    let words: Vec<&str> = args.positional.iter().map(String::as_str).collect();
    match words.as_slice() {
        [] | ["help"] | ["help", ..] => {
            print!("{HELP}");
            Ok(())
        }
        ["version"] => {
            println!("kagami-enforcer {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ["cloudflare", cmd] => cloudflare_command(cmd, &args),
        _ => Err(format!(
            "Unknown command. Run kagami-enforcer help.\n\n{HELP}"
        )),
    }
}

fn cloudflare_command(cmd: &str, args: &Args) -> Result<(), String> {
    // The token is read from the environment only, never from the command
    // line, so it does not end up in shell history or process listings.
    let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
    let account = args
        .get("account", "CLOUDFLARE_ACCOUNT_ID")
        .unwrap_or_default();
    let http = Ureq::default();
    let client = Client::new(&http, &token, &account).map_err(|e| e.0)?;
    let list = || {
        args.get("list", "KAGAMI_CLOUDFLARE_LIST_ID")
            .ok_or_else(|| "Give the list id with --list or KAGAMI_CLOUDFLARE_LIST_ID. Run kagami-enforcer cloudflare setup to create the list.".to_string())
    };
    match cmd {
        "setup" => {
            let name = args
                .get("name", "KAGAMI_CLOUDFLARE_LIST_NAME")
                .unwrap_or_else(|| "kagami_contained".into());
            if name.is_empty()
                || name.len() > 50
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err("The list name may only hold letters, digits and underscores, up to 50 characters.".into());
            }
            let (id, existed) = match client.find_list(&name).map_err(|e| e.0)? {
                Some(id) => (id, true),
                None => (client.create_list(&name).map_err(|e| e.0)?, false),
            };
            println!(
                "{}\n\n  KAGAMI_CLOUDFLARE_LIST_ID={id}\n\nNow add a WAF custom rule in each zone you protect.\n  Dashboard path   Security, then WAF, then Custom rules, then Create rule\n  Expression       (ip.src in ${name})\n  Action           Block, or Managed Challenge for a softer response\n\nThen run kagami-enforcer cloudflare sync --from <contained.json> --watch 30",
                if existed { format!("The IP list \"{name}\" already exists.") } else { format!("Created the IP list \"{name}\".") }
            );
            Ok(())
        }
        "status" => {
            let list = list()?;
            let now = now_ms();
            let items = client.kagami_items(&list).map_err(|e| e.0)?;
            let live = items.iter().filter(|i| i.until_ms > now).count();
            println!(
                "{} Kagami entries in the list, {live} of them active.",
                items.len()
            );
            Ok(())
        }
        "sync" => {
            let list = list()?;
            let from = args
                .get("from", "KAGAMI_BLOCKLIST")
                .ok_or("Give the blocklist file with --from or KAGAMI_BLOCKLIST.")?;
            let by = args
                .get("id", "KAGAMI_ENFORCER_ID")
                .unwrap_or_else(|| "default".into());
            if by.len() > 40
                || !by
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err("The enforcer id may only hold letters, digits, dashes and underscores, up to 40 characters.".into());
            }
            let watch: Option<u64> = match args.get("watch", "KAGAMI_ENFORCER_WATCH") {
                Some(s) => Some(
                    s.parse::<u64>()
                        .ok()
                        .filter(|n| *n >= 5)
                        .ok_or("--watch must be a number of seconds, at least 5.")?,
                ),
                None => None,
            };
            loop {
                let outcome = std::fs::read_to_string(&from)
                    .map_err(|e| format!("Could not read {from} ({e})."))
                    .and_then(|text| blocklist::parse(&text, now_ms()))
                    .and_then(|desired| {
                        cloudflare::sync(&client, &list, &desired, &by, now_ms()).map_err(|e| e.0)
                    });
                match (&outcome, watch) {
                    (Ok(r), _) => {
                        if r.added + r.removed_expired + r.removed_released + r.removed_duplicates
                            > 0
                            || watch.is_none()
                        {
                            println!(
                                "Synced. {} active, {} added, {} expired removed, {} released removed, {} duplicates removed.",
                                r.active, r.added, r.removed_expired, r.removed_released, r.removed_duplicates
                            );
                        }
                    }
                    (Err(e), Some(_)) => eprintln!("Sync failed, will retry. {e}"),
                    (Err(e), None) => return Err(e.clone()),
                }
                match watch {
                    Some(secs) => std::thread::sleep(Duration::from_secs(secs)),
                    None => return Ok(()),
                }
            }
        }
        _ => Err(format!(
            "Unknown cloudflare command \"{cmd}\". Use setup, sync or status."
        )),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
