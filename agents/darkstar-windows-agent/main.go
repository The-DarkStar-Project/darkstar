package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const agentVersion = "0.3.0-native"

type options struct {
	Command         string
	URL             string
	Org             string
	EnrollmentToken string
	AgentToken      string
	ConfigFile      string
	StateFile       string
	Interval        int
	Once            bool
	PrintInventory  bool
	ServiceName     string
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	switch opts.Command {
	case "install":
		must(runInstall(opts))
	case "uninstall":
		must(runUninstall(opts.ServiceName))
	case "start":
		must(runServiceStart(opts.ServiceName))
	case "stop":
		must(runServiceStop(opts.ServiceName))
	case "run", "":
		must(setupLogging(opts))
		must(runServiceOrLoop(opts))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", opts.Command)
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	opts := options{
		Command:     "run",
		ConfigFile:  defaultConfigFile(),
		StateFile:   defaultStateFile(),
		Interval:    3600,
		ServiceName: "DarkstarEndpointAgent",
	}
	if len(args) > 0 {
		switch args[0] {
		case "install", "uninstall", "start", "stop", "run":
			opts.Command = args[0]
			args = args[1:]
		}
	}
	fs := flag.NewFlagSet("darkstar-agent", flag.ContinueOnError)
	fs.StringVar(&opts.URL, "url", "", "Darkstar orchestrator URL")
	fs.StringVar(&opts.Org, "org", "", "Darkstar organization database name for first enrollment")
	fs.StringVar(&opts.EnrollmentToken, "enrollment-token", "", "one-time endpoint enrollment token")
	fs.StringVar(&opts.AgentToken, "agent-token", "", "existing endpoint agent token")
	fs.StringVar(&opts.ConfigFile, "config", opts.ConfigFile, "agent config file")
	fs.StringVar(&opts.StateFile, "state-file", opts.StateFile, "agent state file")
	fs.IntVar(&opts.Interval, "interval", opts.Interval, "inventory interval in seconds")
	fs.BoolVar(&opts.Once, "once", false, "collect and submit one inventory snapshot")
	fs.BoolVar(&opts.PrintInventory, "print-inventory", false, "print collected inventory JSON and exit")
	fs.StringVar(&opts.ServiceName, "service-name", opts.ServiceName, "Windows service name")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	return opts, nil
}

func loadConfig(path string) Config {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("ignoring invalid config %s: %v", path, err)
		return Config{}
	}
	return cfg
}

func writeConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadState(path string) State {
	var state State
	data, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("ignoring invalid state %s: %v", path, err)
		return State{}
	}
	return state
}

func saveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func effectiveConfig(opts options) Config {
	cfg := loadConfig(opts.ConfigFile)
	if opts.URL != "" {
		cfg.URL = opts.URL
	}
	if opts.Org != "" {
		cfg.Org = opts.Org
	}
	if opts.EnrollmentToken != "" {
		cfg.EnrollmentToken = opts.EnrollmentToken
	}
	if opts.AgentToken != "" {
		cfg.AgentToken = opts.AgentToken
	}
	if opts.StateFile != "" {
		cfg.StateFile = opts.StateFile
	}
	if opts.Interval > 0 {
		cfg.IntervalSeconds = opts.Interval
	}
	if cfg.StateFile == "" {
		cfg.StateFile = defaultStateFile()
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 3600
	}
	return cfg
}

func runLoop(ctx context.Context, opts options) error {
	cfg := effectiveConfig(opts)
	if opts.PrintInventory {
		inventory, err := collectInventory(nil)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inventory)
	}
	if cfg.URL == "" {
		return errors.New("--url is required")
	}
	for {
		result, err := runOnce(ctx, cfg, opts.ConfigFile)
		if err != nil {
			log.Printf("inventory run failed: %v", err)
			if opts.Once {
				return err
			}
		} else {
			data, _ := json.Marshal(result)
			log.Print(string(data))
			if opts.Once {
				return nil
			}
		}

		timer := time.NewTimer(time.Duration(cfg.IntervalSeconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runOnce(ctx context.Context, cfg Config, configPath string) (inventoryResponse, error) {
	state := loadState(cfg.StateFile)
	inventory, err := collectInventory(state.NetworkProbeTargets)
	if err != nil {
		return inventoryResponse{}, err
	}
	agentToken := cfg.AgentToken
	if agentToken == "" {
		agentToken = state.AgentToken
	}
	if agentToken == "" {
		if cfg.Org == "" || cfg.EnrollmentToken == "" {
			return inventoryResponse{}, errors.New("--org and --enrollment-token are required for first registration")
		}
		registration, err := register(ctx, cfg.URL, cfg.Org, cfg.EnrollmentToken, inventory)
		if err != nil {
			return inventoryResponse{}, err
		}
		agentToken = registration.AgentToken
		state.AgentID = registration.AgentID
		state.AgentToken = registration.AgentToken
		state.OrgDB = registration.OrgDB
		state.URL = cfg.URL
		if err := saveState(cfg.StateFile, state); err != nil {
			return inventoryResponse{}, err
		}
		if cfg.EnrollmentToken != "" {
			cfg.EnrollmentToken = ""
			if err := writeConfig(configPath, cfg); err != nil {
				log.Printf("failed to scrub enrollment token from config: %v", err)
			}
		}
	}
	result, err := sendInventory(ctx, cfg.URL, agentToken, inventory)
	if err == nil && result.NetworkProbeTargets != nil {
		state.NetworkProbeTargets = result.NetworkProbeTargets
		if saveErr := saveState(cfg.StateFile, state); saveErr != nil {
			log.Printf("failed to save network probe targets: %v", saveErr)
		}
	}
	return result, err
}

func register(ctx context.Context, baseURL string, org string, enrollmentToken string, inventory Inventory) (registerResponse, error) {
	hostname := stringValue(inventory.OS["hostname"])
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	payload := registerRequest{
		Organization:    org,
		EnrollmentToken: enrollmentToken,
		Hostname:        hostname,
		OS:              inventory.OS,
		AgentVersion:    agentVersion,
		Metadata:        inventory.Metadata,
	}
	var result registerResponse
	if err := postJSON(ctx, baseURL, "/api/endpoint-agents/register", "", payload, &result, 30*time.Second); err != nil {
		return result, err
	}
	if !result.OK || result.AgentToken == "" {
		return result, errors.New("registration response did not include an agent token")
	}
	return result, nil
}

func sendInventory(ctx context.Context, baseURL string, agentToken string, inventory Inventory) (inventoryResponse, error) {
	var result inventoryResponse
	err := postJSON(ctx, baseURL, "/api/endpoint-agents/inventory", agentToken, inventory, &result, 5*time.Minute)
	return result, err
}

func postJSON(ctx context.Context, baseURL string, path string, bearerToken string, payload interface{}, out interface{}, timeout time.Duration) error {
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return err
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, path, strings.TrimSpace(string(responseBody)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(responseBody, out)
}

func setupLogging(opts options) error {
	if opts.Command != "run" || opts.PrintInventory {
		return nil
	}
	logPath := defaultLogFile()
	if logPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	return nil
}

func stringValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}
