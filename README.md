# FakeSSH Server

A Go-based SSH server that allows all incoming connections, logs session activity, 
and temporarily bans IPs after repeated attempts.

## Features

- **Input logging**: logs all input from SSH sessions, including command usage and connection details.
- **IP blocking**: limits connection attempts and jails IPs using `ufw`.
- **AbuseIPDB integration**: gets extra IP information if an API key is provided.

## Optional requirements

For IP blocking and automatic unblocking, ensure these tools are installed:
- **`ufw`**: used to block IPs after repeated attempts.
- **`at`**: schedules automatic unblocking of jailed IPs based on configured jail duration.

### Preparation

- `ufw enable`
- `ufw default allow incoming` or `ufw allow 22`

## Installation

See [Releases](https://github.com/jackcvr/fakessh/releases)

## Configuration

`/etc/fakessh/fakessh.toml`:

```toml
verbose = true
bind = "0.0.0.0:22"
timeout = 120
max_attempts = 3
jail_duration = "1 hour"
abuseipdb_key = "your_abuseipdb_api_key"
```

### Logs sample

```shell
{"time":"2024-11-01T22:34:47.556835572Z","level":"INFO","msg":"listening","addr":"0.0.0.0:22"}
{"time":"2024-11-01T22:34:49.397666673Z","level":"INFO","msg":"accepted","addr":{"IP":"47.236.226.119","Port":41654,"Zone":""}}
{"time":"2024-11-01T22:34:49.784598027Z","level":"INFO","msg":"info","ip":"47.236.226.119","data":{"abuseConfidenceScore":100,"countryCode":"SG","domain":"alicloud.com","hostnames":[],"ipAddress":"47.236.226.119","ipVersion":4,"isPublic":true,"isTor":false,"isWhitelisted":false,"isp":"Alibaba Cloud LLC","lastReportedAt":"2024-11-01T19:16:14+00:00","numDistinctUsers":29,"totalReports":237,"usageType":"Data Center/Web Hosting/Transit"}}
{"time":"2024-11-01T22:34:59.86489055Z","level":"INFO","msg":"accepted","addr":{"IP":"47.236.226.119","Port":44480,"Zone":""}}
{"time":"2024-11-01T22:35:08.076343971Z","level":"INFO","msg":"accepted","addr":{"IP":"47.236.226.119","Port":46434,"Zone":""}}
{"time":"2024-11-01T22:35:08.27863929Z","level":"INFO","msg":"jailed","ip":"47.236.226.119","term":"1 day"}
```

## License

[MIT](https://spdx.org/licenses/MIT.html)
