# FakeSSH Server

A Go-based SSH server that allows all incoming connections, logs session activity, 
and temporarily bans IPs after repeated attempts.

## Features

- **Input Logging**: Logs all input from SSH sessions, including command usage and connection details.
- **IP Blocking**: Limits connection attempts and jails IPs using `ufw`.
- **AbuseIPDB Integration**: Gets extra IP information if an API key is provided.
- **Configurable**: Uses a TOML config file to set server options.

## Optional requirements

For IP blocking and automatic unblocking, ensure these tools are installed:
- **`ufw`**: Used to block IPs after repeated failed attempts.
- **`at`**: Schedules automatic unblocking of jailed IPs based on configured jail duration.

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
{"time":"2024-11-01T13:24:52.725948575+02:00","level":"INFO","msg":"listening","addr":"0.0.0.0:22"}
{"time":"2024-11-01T15:46:57.276442767+02:00","level":"INFO","msg":"connected","addr":{"IP":"93.104.211.157","Port":42836,"Zone":""},"user":"pzserver","password":"123456","cmd":"cd ~; chattr -ia .ssh; lockr -ia .ssh"}
{"time":"2024-11-01T15:46:57.276761276+02:00","level":"INFO","msg":"disconnected","addr":{"IP":"93.104.211.157","Port":42836,"Zone":""},"duration":"322.739µs"}
{"time":"2024-11-01T15:46:57.395379839+02:00","level":"INFO","msg":"connected","addr":{"IP":"93.104.211.157","Port":42836,"Zone":""},"user":"pzserver","password":"123456","cmd":"cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~"}
{"time":"2024-11-01T15:46:57.39547434+02:00","level":"INFO","msg":"disconnected","addr":{"IP":"93.104.211.157","Port":42836,"Zone":""},"duration":"77.961µs"}
{"time":"2024-11-01T15:46:57.506277409+02:00","level":"INFO","msg":"info","ip":"93.104.211.157","data":{"abuseConfidenceScore":100,"countryCode":"DE","domain":"contabo.com","hostnames":["vmi22966.contabo.host"],"ipAddress":"93.104.211.157","ipVersion":4,"isPublic":true,"isTor":false,"isWhitelisted":false,"isp":"Contabo GmbH","lastReportedAt":"2024-11-01T13:24:47+00:00","numDistinctUsers":117,"totalReports":140,"usageType":"Data Center/Web Hosting/Transit"}}
```

## License

[MIT](https://spdx.org/licenses/MIT.html)
