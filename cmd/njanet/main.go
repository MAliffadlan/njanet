package main

import (
	"fmt"
	"os"
	"path/filepath"
)

var dbPath string

const apiPort = 8484

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	ifaceName := os.Getenv("NJANET_IFACE")
	if ifaceName == "" {
		ifaceName = autoDetectInterface()
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan":
		cmdScan(ifaceName)
	case "web":
		cmdWeb(ifaceName)
	case "list", "ls":
		cmdList(ifaceName)
	case "protect":
		cmdProtect(ifaceName)
	case "rename", "name":
		cmdRename(ifaceName)
	case "block":
		cmdBlock(ifaceName)
	case "unblock":
		cmdUnblock(ifaceName)
	case "throttle":
		cmdThrottle(ifaceName)
	case "hog", "monopoly", "prioritize":
		cmdHog(ifaceName)
	case "reset":
		cmdReset(ifaceName)
	case "router":
		cmdRouter(ifaceName)
	case "stats":
		cmdStats(ifaceName)
	case "defend":
		cmdDefend(ifaceName)
	case "monitor":
		cmdMonitor(ifaceName)
	case "help", "-h", "--help":
		printUsage()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`NjaNet — Network Controller v0.1

Usage:
  njanet scan              Scan network for devices
  njanet list              List known devices
  njanet block <mac/ip>    Block device
  njanet unblock <mac/ip>  Unblock device
  njanet throttle <mac/ip> <speed> [--watch]  Limit bandwidth
  njanet protect           Manage protected IPs (excluded from hog)
  njanet hog <speed>       Throttle ALL devices except you
  njanet stats             Show network stats
  njanet defend            ARP spoof defense monitor
  njanet reset             Reset all rules
  njanet router            Scan router web interface
  njanet monitor           Live monitor network

Environment:
  NJANET_IFACE  Network interface (default: enp2s0)

Examples:
  njanet scan
  njanet block 192.168.1.100
  njanet throttle 192.168.1.100 1024
`)
}

func init() {
	home := os.Getenv("HOME")
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// When running with sudo, use the original user's home
		home = "/home/" + sudoUser
	}
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot get home dir: %v, using /tmp\n", err)
			home = "/tmp"
		}
	}
	dbPath = filepath.Join(home, ".njanet", "njanet.db")

	if len(os.Args) > 1 && os.Args[1] == "--json" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		os.Setenv("NJANET_JSON", "1")
	}
}
