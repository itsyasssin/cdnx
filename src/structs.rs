use clap::Parser;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::{
        name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
        AsyncResolver, 
    };
use tokio::sync::mpsc;
use std::sync::Arc;


#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub providers: Vec<String>,
    pub interval: u64,
    pub resolvers: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(long_about = None)]
pub struct Args {
    /// comma-sperated ports (e.g 80,443,8000)
    pub ports: Option<String>,

    /// number of threads
    #[arg(short, default_value_t = 500)]
    pub thread: usize,

    /// timeout in miliseconds
    #[arg(short, default_value_t = 2500)]
    pub miliseconds: u64,

    /// append CDN hosts (only with default HTTP ports when ran with a comma-seperated port list)
    #[arg(short, default_value_t = false)]
    pub append: bool,

    /// verbose mode
    #[arg(short, default_value_t = false)]
    pub verbose: bool,
}

pub struct Options {
    pub domain: String,
    pub ip_ranges: Arc<Vec<String>>,
    pub allow: bool,
    pub ports: Arc<Vec<String>>,
    pub permit: tokio::sync::OwnedSemaphorePermit,
    pub tx: mpsc::Sender<()>,
    pub append: bool,
    pub resolver: Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>
}

