package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mectov/njanet/internal/controller"
	"github.com/mectov/njanet/internal/db"
	"github.com/mectov/njanet/internal/scanner"
)

func initDB() *db.Database {
	database, err := db.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	return database
}

func initScanner(ifaceName string) *scanner.Scanner {
	sc, err := scanner.New(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing scanner: %v\n", err)
		os.Exit(1)
	}
	if err := sc.LoadOUI(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: OUI load: %v\n", err)
	}
	return sc
}

func initController(ifaceName string) *controller.Controller {
	return controller.New(ifaceName, getMyIP(ifaceName), getGatewayIP())
}

func autoDetectInterface() string {
	if env := os.Getenv("NJANET_IFACE"); env != "" {
		return env
	}
	out, _ := exec.Command("ip", "-4", "route", "show", "default").Output()
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 5 {
			iface := parts[4]
			ipOut, _ := exec.Command("ip", "-4", "addr", "show", iface).Output()
			if strings.Contains(string(ipOut), "inet ") {
				return iface
			}
		}
	}
	return "enp2s0"
}

func getMyIP(ifaceName string) string {
	cmd := exec.Command("ip", "-4", "addr", "show", ifaceName)
	out, _ := cmd.Output()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.Split(parts[1], "/")[0]
			}
		}
	}
	return "192.168.1.10"
}

func getGatewayIP() string {
	cmd := exec.Command("ip", "route", "show", "default")
	out, _ := cmd.Output()
	parts := strings.Fields(string(out))
	if len(parts) >= 3 {
		return parts[2]
	}
	return "192.168.1.1"
}

func getLocalMAC(ifaceName string) string {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/address")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func resolveGatewayMAC() string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	gatewayIP := getGatewayIP()
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == gatewayIP && fields[3] != "(incomplete)" {
			return strings.ToUpper(fields[3])
		}
	}
	return ""
}
