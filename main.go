package main

import (
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
)

var attempts = make(map[string]int)

var (
	configPath   = "/etc/fakessh/fakessh.toml"
	cmdResponses = map[string]string{
		"uname": "Linux\n",
	}
	jailingReady = false
	connMutex    = sync.Mutex{}
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
		jailingReady = true
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
			resp := makeResponse(cmd)
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
						resp := makeResponse(cmd)
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
			ip := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0]
			slog.Info("accepted", "addr", conn.RemoteAddr())
			if _, ok := attempts[ip]; !ok {
				attempts[ip] = 0
				if config.AbuseIPDBKey != "" {
					go func() {
						info, err := getIPInfo(ip)
						if err != nil {
							slog.Error(err.Error())
							return
						}
						slog.Info("info", "ip", ip, "data", info["data"])
					}()
				}
			}
			attempts[ip] += 1
			if jailingReady && attempts[ip] >= config.MaxAttempts && config.JailDuration != "" {
				if out, err := jailIP(ip); err != nil {
					slog.Error("exec", "error", string(out))
				} else {
					attempts[ip] = 0
					slog.Info("jailed", "ip", ip, "term", config.JailDuration)
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

func makeResponse(cmd string) string {
	list := strings.SplitN(cmd, " ", 2)
	resp, ok := cmdResponses[list[0]]
	if !ok {
		if list[0] == "echo" {
			if len(list) > 1 {
				resp = strings.ReplaceAll(list[1], "'", "")
				resp = strings.ReplaceAll(resp, `"`, "")
			}
			resp += "\n"
		} else {
			resp = fmt.Sprintf("%s: command not found\n", cmd)
		}
	}
	return resp
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

func jailIP(ip string) ([]byte, error) {
	if out, err := exec.Command("ufw", "deny", "from", ip).CombinedOutput(); err != nil {
		return out, err
	} else {
		releaseCmd := fmt.Sprintf(`echo "ufw delete deny from %s" | at now + %s`, ip, config.JailDuration)
		if out, err = exec.Command("/bin/sh", "-c", releaseCmd).CombinedOutput(); err != nil {
			// releasing immediately due to the issues with un-jail scheduling
			_ = exec.Command("ufw", "delete", "deny", "from", ip).Run()
			return out, err
		}
	}
	return nil, nil
}
