package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type ARPDefender struct {
	iface      string
	gatewayIP  string
	gatewayMAC string
	myIP       string
	myMAC      string
	running    bool
	verbose    bool
	alertFunc  func(alert ARPSpoofAlert)
}

type ARPSpoofAlert struct {
	Time      time.Time
	VictimIP  string
	RealMAC   string
	FakeMAC   string
	SpooferIP string
}

func NewARPDefender(iface, gatewayIP, gatewayMAC, myIP, myMAC string) *ARPDefender {
	return &ARPDefender{
		iface:      iface,
		gatewayIP:  gatewayIP,
		gatewayMAC: gatewayMAC,
		myIP:       myIP,
		myMAC:      myMAC,
	}
}

func (d *ARPDefender) SetAlertFunc(f func(alert ARPSpoofAlert)) {
	d.alertFunc = f
}

// Start begins defense monitoring
func (d *ARPDefender) Start(verbose bool) {
	d.running = true
	d.verbose = verbose

	if d.verbose {
		fmt.Println("🛡️ Starting ARP defense...")
		fmt.Printf("   Gateway:  %s = %s (trusted)\n", d.gatewayIP, d.gatewayMAC)
		fmt.Printf("   You:      %s = %s\n", d.myIP, d.myMAC)
		fmt.Println()
	}

	// Store baseline (clean ARP table)
	baseARP := d.readARP()

	go func() {
		for d.running {
			alerts := d.checkARP(baseARP)
			if d.verbose {
				fmt.Printf("\r🛡️ ARP Defense active (%s)      ", time.Now().Format("15:04:05"))
			}

			for _, alert := range alerts {
				d.handleAlert(alert)
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

// Stop stops defense monitoring
func (d *ARPDefender) Stop() {
	d.running = false
	if d.verbose {
		fmt.Println()
		fmt.Println("🛡️ ARP defense stopped")
	}
}

// readARP reads the current ARP table as map[IP]MAC
func (d *ARPDefender) readARP() map[string]string {
	table := make(map[string]string)
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return table
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] != "(incomplete)" && fields[3] != "00:00:00:00:00:00" {
			table[fields[0]] = strings.ToUpper(fields[3])
		}
	}
	return table
}

// checkARP compares current ARP against baseline to detect spoofing
func (d *ARPDefender) checkARP(baseline map[string]string) []ARPSpoofAlert {
	current := d.readARP()
	var alerts []ARPSpoofAlert

	// 1. Check: gateway MAC changed? = Someone spoofing the gateway
	if currentMAC, ok := current[d.gatewayIP]; ok {
		if currentMAC != d.gatewayMAC {
			// Find who is spoofing
			spooferIP := ""
			for ip, mac := range current {
				if mac == currentMAC && ip != d.gatewayIP {
					spooferIP = ip
					break
				}
			}

			alert := ARPSpoofAlert{
				Time:      time.Now(),
				VictimIP:  d.gatewayIP,
				RealMAC:   d.gatewayMAC,
				FakeMAC:   currentMAC,
				SpooferIP: spooferIP,
			}
			alerts = append(alerts, alert)
		}
	}

	// 2. Check: multiple IPs with same MAC = spoofing
	macToIPs := make(map[string][]string)
	for ip, mac := range current {
		if mac != "00:00:00:00:00:00" && mac != d.gatewayMAC {
			macToIPs[mac] = append(macToIPs[mac], ip)
		}
	}
	for mac, ips := range macToIPs {
		if mac != d.myMAC && len(ips) > 2 {
			// Same MAC claiming multiple IPs — suspicious
			alerts = append(alerts, ARPSpoofAlert{
				Time:      time.Now(),
				VictimIP:  ips[0],
				RealMAC:   "unknown",
				FakeMAC:   mac,
				SpooferIP: "multiple",
			})
		}
	}

	return alerts
}

func (d *ARPDefender) handleAlert(alert ARPSpoofAlert) {
	if d.verbose {
		fmt.Printf("\n⚠️  [%s] ARP SPOOF DETECTED!\n", alert.Time.Format("15:04:05"))
		if alert.VictimIP == d.gatewayIP {
			fmt.Printf("   Gateway %s is being spoofed!\n", alert.VictimIP)
			fmt.Printf("   Real MAC:   %s\n", alert.RealMAC)
			fmt.Printf("   Fake MAC:   %s\n", alert.FakeMAC)
			if alert.SpooferIP != "" {
				fmt.Printf("   Sniffer:     %s\n", alert.SpooferIP)
			}
		}
	}

	// Auto-counter: delete fake ARP entry and restore real one
	d.counterMeasure(alert)
}

// counterMeasure restores correct ARP entries
func (d *ARPDefender) counterMeasure(alert ARPSpoofAlert) {
	if d.verbose {
		fmt.Println("   🔧 Restoring ARP...")
	}

	// Delete the fake ARP entry
	exec.Command("arp", "-d", alert.VictimIP).Run()

	// Force correct static ARP entry
	exec.Command("arp", "-s", alert.VictimIP, alert.RealMAC).Run()

	if alert.SpooferIP != "" && d.verbose {
		fmt.Printf("   ✅ Fixed: %s → %s\n", alert.VictimIP, alert.RealMAC)
	}

	if d.alertFunc != nil {
		d.alertFunc(alert)
	}
}
