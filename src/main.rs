mod mercusys;

use clap::Parser;
use mercusys::http::MercusysHTTP;
use reqwest::Url;

/// Mercusys Halo WiFi Mesh Reboot Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Base URL for Mercusys Halo Router
    #[arg(short = 'l', long, default_value = "http://192.168.68.1")]
    url: String,

    /// Router username (internal). If unsure, leave it blank.
    #[arg(short, long, default_value = "admin")]
    user: String,

    /// Router admin password
    #[arg(short, long)]
    password: String,

    /// verbose logging (request body/decrypted response)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// don't actually reboot.
    #[arg(short = 'd', long, default_value_t = false)]
    dry_run: bool,
}

fn main() {
    let args = Args::parse();

    let base_url = Url::parse(args.url.as_str()).unwrap();

    let mut api = MercusysHTTP::new(base_url);
    api.set_logging_enabled(args.verbose);
    api.login(&args.user, &args.password);

    if args.dry_run {
        eprintln!("dry run mode, exit... {:?}", api.logout());

        return;
    }

    let reboot_response = api.reboot_whole_mesh();
    {
        let timeout = reboot_response.result.reboot_time;
        eprintln!("reboot success with wait timeout of {}", timeout);
    }
}
