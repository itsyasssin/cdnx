# CDNX
`cdnx` is a fast and simple tool to cut CDN domains and **exclude them from HTTP port-scanning process**. also you can use it as normal A record resolver.

### Installation
```console
cargo install --git https://github.com/m333rl1n/cdnx.git
```

### Features
```console
$ cdnx -h
Usage: cdnx [OPTIONS] [PORTS]

Arguments:
  [PORTS]  Comma-sperated ports (e.g 80,443,8000)

Options:
  -t <THREAD>      Number of threads [default: 100]
  -a               Append CDN hosts
  -v               Verbose mode
  -h, --help       Print help
```

1. Simply remove CDN domains:
```console
$ printf "noneexists.zzz\nmedium.com\nford.com" | cdnx -t 150
ford.com
```
2. Combine with httpx (or any other tool) to prevent port scan on CDN hosts:
```console
$ printf "noneexists.zzz\nmedium.com\nford.com" | cdnx -a "80,443,8000,5000"
ford.com:80
ford.com:443
ford.com:8000
ford.com:5000
medium.com:80
medium.com:443

$ cat domains.txt | cdnx -a "80,443,8000,5000" | httpx
...
```
3. Use as normal `A` record resolver:
```console
$ printf "noneexists.zzz\nmedium.com\nford.com" | cdnx -a
ford.com
medium.com
```

### Configurations
The configuration file located in `~/.config/cdnx/config.yaml` is in YAML format and contains three main sections:

1. `providers`: A lists of URLs that provide IP ranges for various CDNs. These are fetched periodically to update the list of CDN IPs.
2. `interval`: This field specifies how often (in hours) the application should fetch updates from the providers. The default is set to 48 hours (2 days).
3. `resolvers`: A lists of DNS resolvers to use for IP lookups. These are specified in the format `IP:PORT`.

You can modify the providers, interval, or resolvers as needed for your use case.