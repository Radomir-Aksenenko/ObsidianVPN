package main

import "strings"

const (
	splitModeInclude = "include"
	splitModeExclude = "exclude"
)

func splitTunnelMode(cfg Config) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.SplitTunnelMode))
	switch mode {
	case splitModeInclude, "only", "only_selected", "vpn_only":
		return splitModeInclude
	case splitModeExclude, "except", "all_except", "bypass_selected":
		return splitModeExclude
	}
	if len(splitTunnelEntries(cfg.RouteIPs, nil, nil, nil)) > 0 {
		return splitModeInclude
	}
	return splitModeExclude
}

func splitTunnelEnabled(cfg Config) bool {
	return len(splitTunnelEntries(cfg.RouteIPs, cfg.SplitSites, cfg.SplitApps, cfg.SplitProcesses)) > 0
}

func splitTunnelEntries(routeIPs, sites, apps, processes []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range [][]string{routeIPs, sites, apps, processes} {
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
