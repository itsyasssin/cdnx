# CDNX
`cdnx` is a fast and simple tool to cut CDN domains and **exclude them from HTTP port-scanning process**. also you can use it as normal A record resolver.

### Installation
```console
cargo install --git https://github.com/itsyasssin/cdnx.git
```

### Features
```console
$ cdnx -h
Usage: cdnx [OPTIONS] [PORTS]

Arguments:
  [PORTS]  comma-sperated ports (e.g 80,443,8000)

Options:
  -t <THREAD>           number of threads
  -m <MILISECONDS>      timeout in miliseconds
  -a                    append CDN hosts (only with default HTTP ports when ran with a comma-seperated port list)
  -v                    verbose mode
  -h, --help            Print help
```

1. Simply remove CDN domains:
```console
$ cat hosts.txt 
noneexists.zzz
medium.com
ford.com

$ cat hosts.txt | cdnx
ford.com
```
2. Combine with httpx (or any other tool) to prevent port scan on CDN hosts:
```console
$ cat hosts.txt | cdnx -a "80,443,8000,5000"
ford.com:80
ford.com:443
ford.com:8000
ford.com:5000
medium.com:80
medium.com:443

$ cat hosts.txt | cdnx -a "80,443,8000,5000" | httpx
[OUTPUT]
```
3. Supports URL as input:
```console
$ cat urls.txt
http://non-cdn.com/.env
http://cdn.com/.env

$ cat urls.txt | cdnx 
http://non-cdn.com/.env
$ cat urls.txt | cdnx | httpx
[OUTPUT]
```
4. (recommended) Integrate with something like `puredns` in large data:
```console
$ cat large-1_000_000-data.txt | puredns resolve | cdnx 
```

### Configurations
The configuration file located in `~/.config/cdnx/config.yaml` is in YAML format and contains three main sections:

1. `providers`: A lists of URLs that provide IP ranges for various CDNs. These are fetched periodically to update the list of CDN IPs.
2. `interval`: This field specifies how often (in hours) the application should fetch updates from the providers. The default is set to 48 hours (2 days).
3. `resolvers`: A lists of DNS resolvers to use for IP lookups. These are specified in the format `IP:PORT`.

You can modify the providers, interval, or resolvers as needed for your use case.
