package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type config struct {
	Username username
	Port     int

	// path to config directory.
	path string
}

func getGlobalConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "shh"), nil
}

func getConfigPaths() (global string, project string, err error) {
	global, err = getGlobalConfigPath()
	if err != nil {
		return "", "", fmt.Errorf("global: %w", err)
	}
	project, err = getProjectConfigPath()
	if err != nil {
		return "", "", fmt.Errorf("project: %w", err)
	}
	return global, project, nil
}

func getProjectConfigPath() (string, error) {
	pth, err := findFileRecursive(".shhconfig")
	if os.IsNotExist(err) {
		// If we didn't find any project config, we're done
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find project config: %w", err)
	}
	return pth, nil
}

func configFromPaths(global, project string) (*config, error) {
	globalConfPath := filepath.Join(global, "config")
	fi, err := os.Open(globalConfPath)
	if os.IsNotExist(err) {
		return nil, errors.New("missing keys. run `shh gen-keys`")
	}
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer fi.Close()
	globalConf, err := parseConfig(fi)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	globalConf.path = global

	// If there's no project-specific config, we're done
	if project == "" {
		return globalConf, nil
	}
	fi2, err := os.Open(project)
	if err != nil {
		return nil, fmt.Errorf("open project config: %w", err)
	}
	defer fi2.Close()
	projectConf, err := parseConfig(fi2)
	if err != nil {
		return nil, fmt.Errorf("parse project config: %w", err)
	}

	// Override global config with project-specific settings. Only the
	// username can be overridden now.
	if projectConf.Username != "" {
		globalConf.Username = projectConf.Username
	}

	return globalConf, nil
}

func parseConfig(r io.Reader) (*config, error) {
	conf := &config{}
	scn := bufio.NewScanner(r)
	for i := 1; scn.Scan(); i++ {
		line := scn.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line %d: %s", i, line)
		}
		parts[0] = strings.TrimSpace(parts[0])
		parts[1] = strings.TrimSpace(parts[1])
		switch parts[0] {
		case "username":
			conf.Username = username(parts[1])
		case "port":
			var err error
			conf.Port, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", parts[1], err)
			}
		default:
			return nil, fmt.Errorf("unknown part %s", parts[0])
		}
	}
	if err := scn.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return conf, nil
}
