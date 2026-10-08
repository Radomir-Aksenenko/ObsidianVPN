//go:build linux

package tun

import (
	"log"
	"os"
	"os/exec"
)

const (
	resolvConfPath   = "/etc/resolv.conf"
	resolvBackupPath = "/etc/resolv.conf.obsidian-backup"
)

func systemdResolvedActive() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	if _, err := os.Stat("/run/systemd/resolve"); err != nil {
		return false
	}
	return exec.Command("resolvectl", "status").Run() == nil
}

// applyDNSLinux points the system resolver at dns and returns the restore function.
func applyDNSLinux(tunName, dns string) func() {
	if systemdResolvedActive() {
		if _, err := runCmd("resolvectl", "dns", tunName, dns); err != nil {
			log.Printf("ERROR: resolvectl dns: %v", err)
			return func() {}
		}
		if _, err := runCmd("resolvectl", "domain", tunName, "~."); err != nil {
			log.Printf("ERROR: resolvectl domain: %v", err)
		}
		_, _ = runCmd("resolvectl", "default-route", tunName, "yes")
		_, _ = runCmd("resolvectl", "flush-caches")
		log.Printf("DNS: %s set on %s via systemd-resolved", dns, tunName)
		return func() {
			_, _ = runCmd("resolvectl", "revert", tunName)
		}
	}
	return applyResolvConf(dns)
}

func applyResolvConf(dns string) func() {
	orig, err := os.ReadFile(resolvConfPath)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("ERROR: read %s: %v; DNS not changed", resolvConfPath, err)
		return func() {}
	}
	linkTarget, _ := os.Readlink(resolvConfPath)

	// Keep the very first backup: if a previous run crashed, the file at
	// resolvConfPath is already ours and the backup holds the real original.
	if _, statErr := os.Stat(resolvBackupPath); statErr != nil {
		if werr := os.WriteFile(resolvBackupPath, orig, 0o644); werr != nil {
			log.Printf("ERROR: write %s: %v; DNS not changed", resolvBackupPath, werr)
			return func() {}
		}
	} else {
		log.Printf("DNS: keeping existing %s from an earlier run", resolvBackupPath)
		if data, rerr := os.ReadFile(resolvBackupPath); rerr == nil {
			orig = data
		}
	}

	if linkTarget != "" {
		_ = os.Remove(resolvConfPath) // do not write through the symlink
	}
	if err := os.WriteFile(resolvConfPath, []byte(resolvConfFor(dns)), 0o644); err != nil {
		log.Printf("ERROR: write %s: %v", resolvConfPath, err)
		restoreResolvConf(orig, linkTarget)
		return func() {}
	}
	log.Printf("DNS: %s written to %s (backup: %s)", dns, resolvConfPath, resolvBackupPath)
	return func() { restoreResolvConf(orig, linkTarget) }
}

func restoreResolvConf(orig []byte, linkTarget string) {
	if linkTarget != "" {
		_ = os.Remove(resolvConfPath)
		if err := os.Symlink(linkTarget, resolvConfPath); err != nil {
			log.Printf("ERROR: restore symlink %s: %v", resolvConfPath, err)
			return
		}
	} else if err := os.WriteFile(resolvConfPath, orig, 0o644); err != nil {
		log.Printf("ERROR: restore %s: %v", resolvConfPath, err)
		return
	}
	_ = os.Remove(resolvBackupPath)
}
