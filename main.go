package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gliderlabs/ssh"
	"github.com/pelletier/go-toml/v2"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	APIURL         = "https://api.abuseipdb.com/api/v2/check"
	Prompt         = "root@localhost:~# "
	WelcomeMessage = "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-47-generic x86_64)\n\n"
	JailCapacity   = 1000
)

var attempts = make(map[string]int)

var (
	configPath  = "/etc/fakessh/fakessh.toml"
	jailIsReady = false
	connMutex   = sync.Mutex{}
	httpClient  *http.Client
	IPInfoPool  = sync.Pool{
		New: func() any {
			return new(IPInfo)
		},
	}
)

type IPInfo map[string]any

type Config struct {
	Verbose      bool   `toml:"verbose"`
	Bind         string `toml:"bind"`
	Timeout      int    `toml:"timeout"`
	MaxAttempts  int    `toml:"max_attempts"`
	JailDuration string `toml:"jail_duration"`
	AbuseIPDBKey string `toml:"abuseipdb_key"`
}

var config = Config{
	Verbose:      false,
	Bind:         "0.0.0.0:22",
	Timeout:      60,
	MaxAttempts:  3,
	JailDuration: "1 day",
	AbuseIPDBKey: "",
}

func init() {
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		log.Printf("ufw is not available: %s", out)
		return
	} else {
		if strings.TrimSpace(string(out)) == "Status: inactive" {
			log.Print("ufw installed but is not active")
		}
	}
	out, err = exec.Command("at", "-V").CombinedOutput()
	if err != nil {
		log.Printf("'at' command is not available: %s", out)
	} else {
		jailIsReady = true
	}
}

func main() {
	flag.StringVar(&configPath, "c", configPath, "Path to TOML config file")
	flag.Parse()

	if data, err := os.ReadFile(configPath); err != nil {
		panic(err)
	} else if err = toml.Unmarshal(data, &config); err != nil {
		panic(err)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	level := slog.LevelInfo
	if config.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	ssh.Handle(func(sess ssh.Session) {
		defer Catch(func(err error) {
			slog.Error(err.Error())
		})
		start := time.Now()
		defer func() {
			_ = sess.Exit(0)
			slog.Info("disconnected", "addr", sess.RemoteAddr(), "duration", time.Now().Sub(start).String())
		}()

		ctx := sess.Context()
		cmd := sess.RawCommand()
		slog.Info("auth",
			"addr", sess.RemoteAddr(),
			"user", ctx.User(),
			"password", ctx.Value("password"),
			"cmd", cmd)

		if cmd != "" {
			resp := fmt.Sprintf("%s: command not found\n", cmd)
			Try(sess.Write([]byte(resp)))
			slog.Debug("output", "cmd", resp)
		} else {
			Try(sess.Write([]byte(WelcomeMessage + Prompt)))
			go func() {
				defer Catch(func(err error) {
					slog.Debug(err.Error())
				})
				input := make([]byte, 0, 1024)
				buf := []byte{0}
				for {
					if IsDone(ctx) {
						return
					}
					Try(sess.Read(buf))
					input = append(input, buf...)
					Try(sess.Write(buf))
					if buf[0] == 13 {
						Try(sess.Write([]byte("\n")))
						cmd = strings.TrimSpace(string(input))
						slog.Info("input",
							"addr", sess.RemoteAddr(),
							"cmd", cmd)
						resp := fmt.Sprintf("%s: command not found\n", cmd)
						Try(sess.Write([]byte(resp + Prompt)))
						slog.Debug("output", "cmd", resp)
						input = input[:0]
					}
				}
			}()
			timer := time.NewTimer(time.Duration(config.Timeout) * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	})

	slog.Info("listening", "addr", config.Bind)
	slog.Error(ssh.ListenAndServe(config.Bind, nil,
		ssh.WrapConn(func(ctx ssh.Context, conn net.Conn) net.Conn {
			connMutex.Lock()
			defer connMutex.Unlock()
			slog.Info("accepted", "addr", conn.RemoteAddr())
			ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				slog.Error(err.Error())
				return conn
			}
			if len(attempts) < JailCapacity {
				if _, ok := attempts[ip]; !ok {
					attempts[ip] = 0
					if config.AbuseIPDBKey != "" {
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
							defer cancel()
							info := IPInfoPool.Get().(*IPInfo)
							defer IPInfoPool.Put(info)
							if err = getIPInfo(ctx, info, ip); err != nil {
								slog.Error(err.Error())
								return
							}
							slog.Info("info", "ip", ip, "data", (*info)["data"])
						}()
					}
				}
				attempts[ip] += 1
				if attempts[ip] >= config.MaxAttempts && jailIsReady && config.JailDuration != "" {
					defer delete(attempts, ip)
					if info, err := jailIP(ip); err != nil {
						slog.Error("exec", "error", string(info))
					} else {
						slog.Info("jailed", "ip", ip, "term", config.JailDuration)
					}
				}
			}
			return conn
		}),
		ssh.PasswordAuth(func(ctx ssh.Context, pw string) bool {
			ctx.SetValue("password", pw)
			return true
		}),
	).Error())
}

func getIPInfo(ctx context.Context, data *IPInfo, ip string) error {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	url := fmt.Sprintf("%s?ipAddress=%s", APIURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", config.AbuseIPDBKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(string(body))
	}
	if err = json.Unmarshal(body, data); err != nil {
		return err
	}
	return nil
}

func jailIP(ip string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "ufw", "deny", "from", ip).CombinedOutput(); err != nil {
		return out, err
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		releaseCmd := fmt.Sprintf(`echo "ufw delete deny from %s" | at now + %s`, ip, config.JailDuration)
		if out, err = exec.CommandContext(ctx, "/bin/sh", "-c", releaseCmd).CombinedOutput(); err != nil {
			// releasing immediately due to the issues with un-jail scheduling
			_ = exec.Command("ufw", "delete", "deny", "from", ip).Run()
			return out, err
		}
	}
	return nil, nil
}
