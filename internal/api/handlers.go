package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/mectov/njanet/internal/controller"
	"github.com/mectov/njanet/internal/db"
	"github.com/mectov/njanet/internal/scanner"
)

type Server struct {
	db         *db.Database
	scanner    *scanner.Scanner
	controller *controller.Controller
	server     *http.Server
	scanCache  *scanner.ScanResult
	lastScan   time.Time
}

func New(database *db.Database, sc *scanner.Scanner, ctrl *controller.Controller) *Server {
	return &Server{
		db:         database,
		scanner:    sc,
		controller: ctrl,
	}
}

func (s *Server) Start(port int) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/devices/", s.handleDeviceByMAC)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/block", s.handleBlock)
	mux.HandleFunc("/api/unblock", s.handleUnblock)
	mux.HandleFunc("/api/throttle", s.handleThrottle)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/reset", s.handleReset)

	// Web UI
	mux.Handle("/", http.FileServer(http.Dir("internal/ui/web/static")))

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: corsMiddleware(mux),
	}

	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// GET /api/devices
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.db.GetAllDevices()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	// Get active throttle/block rules
	rules := s.controller.GetActiveRules()
	for _, dev := range devices {
		if rule, ok := rules[dev.MAC]; ok {
			dev.SpeedLimit = rule.SpeedLimit
			dev.Blocked = rule.Blocked
		}
	}

	writeJSON(w, map[string]interface{}{
		"devices": devices,
		"total":   len(devices),
	})
}

// GET /api/devices/{mac}
func (s *Server) handleDeviceByMAC(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Path[len("/api/devices/"):]
	if mac == "" {
		writeError(w, 400, "MAC required")
		return
	}

	dev, err := s.db.GetDeviceByMAC(mac)
	if err != nil {
		writeError(w, 404, "device not found")
		return
	}

	writeJSON(w, dev)
}

// POST /api/scan
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "POST required")
		return
	}

	ctx := context.Background()
	result, err := s.scanner.Scan(ctx)
	if err != nil {
		writeError(w, 500, fmt.Sprintf("scan failed: %v", err))
		return
	}

	// Store devices in DB
	for _, dev := range result.Devices {
		id, err := s.db.UpsertDevice(dev)
		if err == nil {
			_ = id
		}
	}

	s.scanCache = result
	s.lastScan = time.Now()

	// Log scan
	s.db.LogScan(result.Total, result.Online)

	writeJSON(w, result)
}

// POST /api/block
func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "POST required")
		return
	}

	var req struct {
		MAC string `json:"mac"`
		IP  string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid request")
		return
	}

	dev, err := s.db.GetDeviceByMAC(req.MAC)
	if err != nil {
		// Create temporary device
		dev = &db.Device{
			MAC:    req.MAC,
			IP:     req.IP,
			Online: true,
		}
	}

	if err := s.controller.BlockDevice(dev); err != nil {
		writeError(w, 500, fmt.Sprintf("block failed: %v", err))
		return
	}

	s.db.UpdateDeviceBlock(req.MAC, true)
	writeJSON(w, map[string]string{"status": "blocked", "mac": req.MAC})
}

// POST /api/unblock
func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "POST required")
		return
	}

	var req struct {
		MAC string `json:"mac"`
		IP  string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid request")
		return
	}

	dev, err := s.db.GetDeviceByMAC(req.MAC)
	if err != nil {
		dev = &db.Device{MAC: req.MAC, IP: req.IP}
	}

	if err := s.controller.UnblockDevice(dev); err != nil {
		writeError(w, 500, fmt.Sprintf("unblock failed: %v", err))
		return
	}

	s.db.UpdateDeviceBlock(req.MAC, false)
	writeJSON(w, map[string]string{"status": "unblocked", "mac": req.MAC})
}

// POST /api/throttle
func (s *Server) handleThrottle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "POST required")
		return
	}

	var req struct {
		MAC    string `json:"mac"`
		IP     string `json:"ip"`
		Speed  int    `json:"speed"` // Kbps, 0 = unlimited
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid request")
		return
	}

	if req.Speed < 0 {
		writeError(w, 400, "speed must be >= 0")
		return
	}

	dev, err := s.db.GetDeviceByMAC(req.MAC)
	if err != nil {
		dev = &db.Device{MAC: req.MAC, IP: req.IP}
	}

	if req.Speed == 0 {
		s.controller.UnblockDevice(dev)
		s.controller.ThrottleDevice(dev, 0)
		s.db.UpdateDeviceSpeed(req.MAC, 0)
		writeJSON(w, map[string]interface{}{
			"status": "unlimited",
			"mac":    req.MAC,
			"speed":  0,
		})
		return
	}

	if err := s.controller.ThrottleDevice(dev, req.Speed); err != nil {
		writeError(w, 500, fmt.Sprintf("throttle failed: %v", err))
		return
	}

	s.db.UpdateDeviceSpeed(req.MAC, req.Speed)
	writeJSON(w, map[string]interface{}{
		"status": "throttled",
		"mac":    req.MAC,
		"speed":  req.Speed,
	})
}

// GET /api/traffic
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("mac")
	since := r.URL.Query().Get("since")

	sinceTime := time.Now().Add(-1 * time.Hour)
	if since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			sinceTime = time.Now().Add(-d)
		}
	}

	var records []*db.TrafficRecord
	var err error

	if mac != "" {
		records, err = s.db.GetTrafficByMAC(mac, sinceTime)
	} else {
		// Return all traffic
		records = []*db.TrafficRecord{}
	}

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"records": records,
		"since":   sinceTime,
	})
}

// GET /api/stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	devices, _ := s.db.GetAllDevices()
	scans, _ := s.db.GetRecentScans(10)

	totalOnline := 0
	totalTrafficIn := int64(0)
	totalTrafficOut := int64(0)
	totalBlocked := 0

	for _, dev := range devices {
		if dev.Online {
			totalOnline++
		}
		totalTrafficIn += dev.TrafficIn
		totalTrafficOut += dev.TrafficOut
		if dev.Blocked {
			totalBlocked++
		}
	}

	// Get current rules
	rules := s.controller.GetActiveRules()
	throttledCount := 0
	for _, rule := range rules {
		if rule.SpeedLimit > 0 {
			throttledCount++
		}
	}

	writeJSON(w, map[string]interface{}{
		"total_devices":   len(devices),
		"online_devices":  totalOnline,
		"blocked_devices": totalBlocked,
		"throttled":       throttledCount,
		"traffic_in":      totalTrafficIn,
		"traffic_out":     totalTrafficOut,
		"my_ip":           s.scanner.MyIP().String(),
		"subnet":          s.scanner.Subnet().String(),
		"last_scan":       s.lastScan,
		"scan_history":    scans,
	})

	// Also try tc stats
	if tcStats, err := s.controller.GetTrafficStats(); err == nil {
		// Merge into response
		_ = tcStats
	}
}

// POST /api/reset
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "POST required")
		return
	}

	if err := s.controller.Reset(); err != nil {
		writeError(w, 500, fmt.Sprintf("reset failed: %v", err))
		return
	}

	writeJSON(w, map[string]string{"status": "reset"})
}

// StartBackground starts the API server in a goroutine
func (s *Server) StartBackground(port int) {
	go func() {
		if err := s.Start(port); err != nil && err != http.ErrServerClosed {
			fmt.Printf("API server error: %v\n", err)
		}
	}()
}
