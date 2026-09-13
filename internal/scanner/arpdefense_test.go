package scanner

import (
	"testing"
	"time"
)

func TestNewARPDefenderNormalizesMAC(t *testing.T) {
	d := NewARPDefender("eth0", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.10", "11:22:33:44:55:66")
	if d.gatewayMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("gatewayMAC = %q, want uppercase", d.gatewayMAC)
	}
	if d.myMAC != "11:22:33:44:55:66" {
		t.Errorf("myMAC = %q, want uppercase", d.myMAC)
	}
}

// Start/Stop berulang di bawah -race detector: flag running harus aman
// diakses lintas goroutine (dulu bool biasa = data race).
func TestARPDefenderStartStop(t *testing.T) {
	for i := 0; i < 20; i++ {
		d := NewARPDefender("eth0", "192.168.1.1", "AA:BB:CC:DD:EE:FF", "192.168.1.10", "11:22:33:44:55:66")
		d.Start(false)
		time.Sleep(time.Millisecond)
		d.Stop()
		if d.running.Load() {
			t.Fatal("running should be false after Stop")
		}
	}
}
