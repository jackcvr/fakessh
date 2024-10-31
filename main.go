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
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	APIURL         = "https://api.abuseipdb.com/api/v2/check"
	Prompt         = "root@localhost:~# "
	WelcomeMessage = "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-47-generic x86_64)\n\n"
)

var attempts = make(map[string]int)

var (
	configPath   = "/etc/fakessh/fakessh.toml"
	cmdResponses = map[string]string{
		"uname": "Linux\n",
	}
)

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
		defer catch(func(err error) {
			slog.Error(err.Error())
		})
		start := time.Now()
		defer func() {
			_ = sess.Exit(0)
			slog.Info("disconnected", "addr", sess.RemoteAddr(), "duration", time.Now().Sub(start).String())
		}()

		ctx := sess.Context()
		pw := ctx.Value("password")
		cmd := sess.RawCommand()
		slog.Info("connected", "addr", sess.RemoteAddr(), "user", ctx.User(), "password", pw, "cmd", cmd)

		ip := strings.SplitN(sess.RemoteAddr().String(), ":", 2)[0]
		if _, ok := attempts[ip]; !ok {
			attempts[ip] = 0
			go func() {
				info, err := getIPInfo(ip)
				if err != nil {
					slog.Error(err.Error())
					return
				}
				slog.Info("info", "ip", ip, "data", info["data"])
			}()
		}
		attempts[ip] += 1

		if attempts[ip] >= config.MaxAttempts {
			attempts[ip] = 0
			if out, err := exec.Command("ufw", "deny", "from", ip).CombinedOutput(); err != nil {
				slog.Error("exec", "error", string(out))
			}
			cleanupCmd := fmt.Sprintf(`echo "ufw delete deny from %s" | at now + %s`, ip, config.JailDuration)
			if out, err := exec.Command("/bin/sh", "-c", cleanupCmd).CombinedOutput(); err != nil {
				slog.Error("exec", "error", string(out))
			}
			slog.Info("ban", "ip", ip, "term", config.JailDuration)
		}

		if cmd != "" {
			cmd0 := sess.Command()[0]
			resp := makeResponse(cmd0)
			try(sess.Write([]byte(resp)))
			slog.Debug("cmd", "sent", resp)
			return
		} else {
			try(sess.Write([]byte(WelcomeMessage + Prompt)))
		}

		if cmd == "" {
			go func() {
				defer catch(func(err error) {
					slog.Debug(err.Error())
				})
				input := make([]byte, 0, 1024)
				buf := []byte{0}
				for {
					if isDone(ctx) {
						return
					}
					try(sess.Read(buf))
					input = append(input, buf...)
					try(sess.Write(buf))
					if buf[0] == 13 {
						try(sess.Write([]byte("\n")))
						rawCmd := strings.TrimSpace(string(input))
						slog.Info("input",
							"addr", sess.RemoteAddr(),
							"cmd", rawCmd)
						cmd0 := strings.SplitN(rawCmd, " ", 2)[0]
						resp := makeResponse(cmd0)
						try(sess.Write([]byte(resp + Prompt)))
						slog.Debug("output", "cmd", resp)
						input = input[:0]
					}
				}
			}()
		}

		timer := time.NewTimer(time.Duration(config.Timeout) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	})

	slog.Info("listening", "addr", config.Bind)
	slog.Error(ssh.ListenAndServe(config.Bind, nil,
		ssh.PasswordAuth(func(ctx ssh.Context, pw string) bool {
			ctx.SetValue("password", pw)
			return true
		}),
	).Error())
}

func makeResponse(cmd string) string {
	resp, ok := cmdResponses[cmd]
	if !ok {
		resp = fmt.Sprintf("%s: command not found\n", cmd)
	}
	return resp
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func getIPInfo(ip string) (map[string]any, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s?ipAddress=%s", APIURL, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Key", config.AbuseIPDBKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(string(body))
	}

	data := make(map[string]any)
	if err = json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data, nil
}
