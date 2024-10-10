use cdnx::structs::Args;
use cdnx::utils::{load_config, make_tokio_asyncresolver, read_cidrs, process};
use clap::Parser;
use std::error::Error;
use std::io::{self, BufRead};
use std::sync::Arc;
use tokio;
use tokio::sync::{mpsc, Semaphore};
use cdnx::structs::Options;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut ports: Vec<String> = Vec::new();

    if let Some(p) = args.ports {
        ports = p.split(',').map(|p| p.to_string()).collect();
    }
    let ports: Arc<Vec<String>> = Arc::from(ports);

    let allow_print_ports = ports.len() != 0;

    let config = load_config(args.verbose).await;
    let ip_ranges: Arc<Vec<String>> = Arc::from(read_cidrs());

    let stdin = io::stdin().lock();
    let (tx, mut rx) = mpsc::channel(args.thread);
    let semaphore = Arc::new(Semaphore::new(args.thread));
    let runtime = tokio::runtime::Runtime::new()?;
    let resolver = Arc::new(make_tokio_asyncresolver(config.resolvers, args.miliseconds));

    for line in stdin.lines() {
        let domain = line.unwrap().trim().to_string();

        if domain.starts_with("*") {
            continue;
        }

        let options = Options {
            allow: allow_print_ports,
            domain: domain,
            ip_ranges: ip_ranges.clone(),
            permit: semaphore.clone().acquire_owned().await.unwrap(),
            tx: tx.clone(),
            append: args.append,
            ports: ports.clone(),
            resolver: resolver.clone()
        };

        runtime.spawn(process(options));
    }

    drop(tx);

    // Wait for all tasks to complete
    while rx.recv().await.is_some() {}

    runtime.shutdown_background();

    Ok(())
}
