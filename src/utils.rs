use std::net::SocketAddr;
use trust_dns_resolver::{
    config::{
        LookupIpStrategy, NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig,
        ResolverOpts,
    },
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    AsyncResolver, TokioAsyncResolver,
};

use crate::structs::{Config, Options};
use regex::Regex;
use reqwest::{Client, Url};
use serde_yaml;
use std::error::Error;
use std::io::{self, Write};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs};
use tokio;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::channel;
use lazy_static::lazy_static;
use include_dir::{include_dir, Dir};

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");
const IPV4_CIDR_REGEX: &str = r#"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/(3[0-2]|[1-2][0-9]|[0-9]))"#;
const BLUE: &str = "\x1b[34m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

lazy_static! {
    // define global accessable dynamic varables
    static ref Home: String = env::var("HOME").expect("Failed to read $HOME environment variable");
    static ref BaseDir: PathBuf = PathBuf::from(Home.to_owned() + "/.config/cdnx");
    static ref Update_File: PathBuf = BaseDir.join("last_update");
    static ref CIDR_File: PathBuf = BaseDir.join("cidr.txt");
    static ref Config_File: PathBuf = BaseDir.join("config.yaml");
    
}

pub async fn process(options: Options) {
    let mut this_domain = options.domain.clone();
    let mut is_url = false;
    
    // if domain is a url, we need to get the host name
    if options.domain.starts_with("http://") || options.domain.starts_with("https://") {
        this_domain = options.domain.parse::<Url>().unwrap().host_str().unwrap().to_owned();
        is_url = true;
    }

    let mut ip: String = String::new();
    match this_domain.parse::<IpAddr>() {
        Ok(_) => ip = options.domain.clone(),
        Err(__) => {
            if let Ok(response) = options
                .resolver
                .lookup_ip(this_domain.as_str().to_owned() + ".")
                .await
            {
                if let Some(addr) = response.iter().next() {
                    if addr.is_ipv4() {
                        ip = addr.to_string()
                    }
                }
            }
        }
    }

    if ip.is_empty() {
        return ();
    }
    let is_this_cdn = is_cdn(&options.ip_ranges, &ip);

    if !options.allow && (options.append || !is_cdn(&options.ip_ranges, &ip)){
        let _ = writeln!(io::stdout(), "{0}", options.domain);
        return ();
    }

    if is_this_cdn && options.append && !is_url {
        let _ = writeln!(io::stdout(), "{0}:80\n{0}:443", options.domain);
        return ();
    }
    if !is_this_cdn && !is_url {
        for port in options.ports.iter() {
            let _ = writeln!(io::stdout(), "{0}:{1}", options.domain, port);
        }
    }

    drop(options.permit);
    let _ = options.tx.send(()).await;
}

pub fn make_tokio_asyncresolver(
    nameserver_ips: Vec<String>,
    timeout: u64
) -> AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>> {
    let options = ResolverOpts {
        timeout: std::time::Duration::from_millis(timeout),
        attempts: 0,
        ip_strategy: LookupIpStrategy::Ipv4Only,
        num_concurrent_reqs: 2,
        ..Default::default()
    };
    let mut name_servers = NameServerConfigGroup::with_capacity(nameserver_ips.len() * 2);

    name_servers.extend(nameserver_ips.into_iter().flat_map(|server| {
        let socket_addr = SocketAddr::V4(match server.parse() {
            Ok(a) => a,
            Err(e) => unreachable!(
                "Error parsing the server {}, only IPv4 are allowed. Error: {}",
                server, e
            ),
        });

        std::iter::once(NameServerConfig {
            socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
        })
        .chain(std::iter::once(NameServerConfig {
            socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
        }))
    }));

    TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], name_servers),
        options,
    )
    .unwrap()
}

/// read "~/.config/cdnx/last_update"
fn read_update_time() -> u64 {
    let path = Update_File.to_owned();
    match fs::read_to_string(&path) {
        Ok(data) => {
            data.parse::<u64>().expect(&format!("Failed to parse {0:?}", &path))
        },
        Err(_) => {
            fs::write(&path, "1").expect(&format!("Failed to write {0:?}", path));
            1
        }
    }
}

/// insert update epoch time to "~/.config/cdnx/last_update"
fn insert_update_time() {
    let path = Update_File.to_owned();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fs::write(&path, now.to_string()).expect(&format!("Failed to write {0:?}", path));
}

/// read "~/.config/cdnx/config.yaml"
fn read_cfg() -> Config {
    let path = Config_File.to_owned();
    let data = fs::read_to_string(&path).expect(&format!("Failed to read {0:?}", &path));
    let config: Config =
        serde_yaml::from_str(&data).expect(&format!("Failed to parse {0:?}", path));
    config
}
/// write static dir files to "~/.config/cdnx/"
fn write_cfg() {
    let path = BaseDir.to_owned();
    fs::create_dir_all(&path).expect(&format!("Failed to create {0:?}", &path));

    for file in STATIC_DIR.files() {
        let file_path = path.join(file.path());
        let content = file.contents();
        fs::write(&file_path, content).expect(&format!("Failed to write {file:?}"));
    }
}

fn logger(color: &str, sign: &str, msg: &str, verbose: bool) {
    if verbose {
        let _ = writeln!(io::stderr(), "[{}{}{RESET}] {}", color, sign, msg);
    }
}

fn is_cdn(cidrs: &Vec<String>, ip: &str) -> bool {
    for cidr_str in cidrs {
        if let Ok((network_ip, prefix_len)) = parse_cidr(&cidr_str) {
            if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                let is_in_range = is_ip_in_cidr(ip, network_ip, prefix_len);
                if is_in_range {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format".into());
    }

    let ip = Ipv4Addr::from_str(parts[0])?;
    let prefix_len: u8 = parts[1].parse()?;

    if prefix_len > 32 {
        return Err("Prefix length must be between 0 and 32".into());
    }

    Ok((ip, prefix_len))
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

fn is_ip_in_cidr(ip: Ipv4Addr, network_ip: Ipv4Addr, prefix_len: u8) -> bool {
    let ip_u32 = ipv4_to_u32(ip);
    let network_ip_u32 = ipv4_to_u32(network_ip);
    let netmask_u32 = !0u32 << (32 - prefix_len);
    (ip_u32 & netmask_u32) == (network_ip_u32 & netmask_u32)
}

/// read "~/.config/cdnx/cidr.txt"
pub fn read_cidrs() -> Vec<String> {
    let path = CIDR_File.to_owned();

    fs::read_to_string(&path)
        .expect(&format!("Failed to read {0:?}", path))
        .trim()
        .lines()
        .map(|l| l.trim().to_string())
        .collect()
}

/// Fetch new CIDRs from providers
async fn update_cidrs(
    providers: Vec<String>,
    path: &Path,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    let reg: Regex = Regex::new(IPV4_CIDR_REGEX).unwrap();
    logger(BLUE, "+", "Updating ...", verbose);
    let mut handles = vec![];
    let (cx, mut rx) = channel(100);
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    for url_value in providers {
        let url = url_value;
        let r = reg.clone();
        let cx_clone = cx.clone();
        let client_clone = client.clone();

        let handle = tokio::spawn(async move {
            match client_clone.get(url.clone()).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        // Read the response body
                        let body = response.text().await.unwrap();
                        // Find CIDRs with regex in response body
                        let cidrs = r.captures_iter(&body);
                        for cidr in cidrs.into_iter() {
                            let c = cidr.get(0).unwrap().as_str().to_string();
                            cx_clone.send(c).await.unwrap();
                        }

                        logger(BLUE, "+", &format!("{url} DONE"), verbose);
                    } else {
                        logger(
                            YELLOW,
                            "!",
                            &format!("Failed to fetch {url} with status {}", response.status()),
                            verbose,
                        );
                    }
                }
                Err(_) => {
                    logger(YELLOW, "!", &format!("Failed to fetch {url}"), verbose);
                }
            }
        });

        handles.push(handle);
    }

    let mut file: tokio::fs::File = tokio::fs::File::create(path).await.unwrap();
    let mut is_err = true;
    drop(cx);
    while let Some(i) = rx.recv().await {
        is_err = false;
        let _ = file.write_all(format!("{i}\n").as_bytes()).await;
    }

    if is_err {
        logger(RED, "#", "Could't fetch any CIDR :(", true);
        exit(1);
    } else {
        logger(BLUE, "+", "Updated successfully", verbose);
        insert_update_time();
    }

    Ok(())
}

/// load ~/.config/cdnx/config.yaml and check for updates
pub async fn load_config(verbose: bool) -> Config {
    // if "~/.config/cdnx" and "~/.config/cdnx/config.yaml" exists
    if BaseDir.exists() && Config_File.exists() {

        let config: Config = read_cfg();

        let last_update_time = read_update_time();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // if time passed from last update was lower than interval
        if ((now - last_update_time) > (config.interval * 3600)) || !CIDR_File.exists() {
            update_cidrs(config.providers.clone(), &CIDR_File, verbose)
                .await
                .unwrap();
        }
        return config
    } else {
        write_cfg();
        let config: Config = read_cfg();

        update_cidrs(config.providers.clone(), &CIDR_File, verbose)
            .await
            .unwrap();
        config
    }
}
