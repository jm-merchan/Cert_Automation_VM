package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vault-secret-inventory/internal/alerter"
	"vault-secret-inventory/internal/scanner"
	"vault-secret-inventory/internal/state"
	"vault-secret-inventory/internal/types"
	"vault-secret-inventory/internal/vaultclient"
)

//go:embed templates/* static/*
var webFS embed.FS

type Server struct {
	state      *state.AppState
	scanMu     sync.Mutex
	eventMu    sync.Mutex
	eventStop  context.CancelFunc
	eventGen   uint64
	alerter    *alerter.Service
	templates  *template.Template
	httpServer *http.Server
}

func main() {
	cfg := types.AppConfig{
		OrangeThresholdMinutes: 30,
		RedThresholdMinutes:    60,
		ScanIntervalSeconds:    120,
		EventTopic:             "kv*",
	}
	appState := state.New(cfg)
	tmpl, err := template.ParseFS(webFS, "templates/index.html")
	if err != nil {
		log.Fatalf("template parse failed: %v", err)
	}

	s := &Server{
		state:     appState,
		alerter:   alerter.New(),
		templates: tmpl,
	}

	staticFS, err := fs.Sub(webFS, "static")
	if err != nil {
		log.Fatalf("static fs init failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/namespaces", s.handleNamespaces)
	mux.HandleFunc("/api/secrets", s.handleSecrets)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/events", s.handleEvents)

	s.httpServer = &http.Server{
		Addr:              ":8080",
		Handler:           withCORS(loggingMiddleware(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go s.scanLoop(context.Background())
	go s.ensureEventListener()

	log.Println("Vault Secret Inventory listening on http://localhost:8080")
	if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg, namespaces, _, _, lastScan, errs := s.state.Snapshot()
	view := map[string]interface{}{
		"Config":     cfg,
		"Namespaces": namespaces,
		"LastScan":   lastScan,
		"Errors":     errs,
	}
	if err := s.templates.ExecuteTemplate(w, "index.html", view); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.state.GetConfig()
		writeJSON(w, http.StatusOK, cfg)
	case http.MethodPost:
		var cfg types.AppConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		cfg.ApplyDefaults()
		if strings.TrimSpace(cfg.VaultAddress) == "" || strings.TrimSpace(cfg.PeriodicToken) == "" {
			writeError(w, http.StatusBadRequest, "vaultAddress and periodicToken are required")
			return
		}
		s.state.SetConfig(cfg)
		s.ensureEventListener()
		go s.runScan(context.Background())
		writeJSON(w, http.StatusOK, map[string]string{"status": "config updated"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	res, err := s.runScan(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "scan completed",
		"startedAt":   res.StartedAt,
		"completedAt": res.CompletedAt,
		"namespaces":  len(res.Namespaces),
		"secrets":     len(res.Secrets),
		"alerts":      len(res.Alerts),
		"errors":      res.ScanErrors,
	})
}

func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, namespaces, _, _, lastScan, _ := s.state.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"lastScan":   lastScan,
		"namespaces": namespaces,
	})
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	filter := strings.Trim(r.URL.Query().Get("namespace"), "/")
	_, _, secrets, _, lastScan, errs := s.state.Snapshot()
	filtered := []types.SecretRecord{}
	for _, sec := range secrets {
		ns := strings.Trim(sec.Namespace, "/")
		if filter == "" || ns == filter {
			filtered = append(filtered, sec)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"lastScan": lastScan,
		"total":    len(filtered),
		"errors":   errs,
		"secrets":  filtered,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, _, _, alerts, lastScan, _ := s.state.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"lastScan": lastScan,
		"total":    len(alerts),
		"alerts":   alerts,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	events, running, streamErr := s.state.EventsSnapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"running": running,
		"error":   streamErr,
		"total":   len(events),
		"events":  events,
	})
}

func (s *Server) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	lastRun := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := s.state.GetConfig()
			if strings.TrimSpace(cfg.VaultAddress) == "" || strings.TrimSpace(cfg.PeriodicToken) == "" {
				continue
			}
			if lastRun.IsZero() || time.Since(lastRun) >= time.Duration(cfg.ScanIntervalSeconds)*time.Second {
				if _, err := s.runScan(context.Background()); err != nil {
					log.Printf("background scan failed: %v", err)
				}
				lastRun = time.Now()
			}
		}
	}
}

func (s *Server) runScan(ctx context.Context) (types.ScanResult, error) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	cfg := s.state.GetConfig()
	cfg.ApplyDefaults()
	if strings.TrimSpace(cfg.VaultAddress) == "" || strings.TrimSpace(cfg.PeriodicToken) == "" {
		return types.ScanResult{}, errors.New("vaultAddress and periodicToken must be configured")
	}

	vault := vaultclient.New(cfg.VaultAddress, cfg.PeriodicToken)
	scannerSvc := scanner.New(vault)
	res, err := scannerSvc.Scan(ctx, cfg)
	if err != nil {
		return res, err
	}

	if err := s.alerter.NotifyWebhook(ctx, cfg.WebhookURL, res.Alerts); err != nil {
		res.WebhookErrors = append(res.WebhookErrors, err.Error())
	}

	s.state.SetScan(res.Namespaces, res.Secrets, res.Alerts, mergeErrors(res.ScanErrors, res.WebhookErrors), res.CompletedAt)
	return res, nil
}

func (s *Server) ensureEventListener() {
	s.eventMu.Lock()
	if s.eventStop != nil {
		s.eventStop()
		s.eventStop = nil
	}

	cfg := s.state.GetConfig()
	cfg.ApplyDefaults()
	if strings.TrimSpace(cfg.VaultAddress) == "" || strings.TrimSpace(cfg.PeriodicToken) == "" {
		s.state.SetEventStatus(false, nil)
		s.eventMu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.eventStop = cancel
	gen := atomic.AddUint64(&s.eventGen, 1)
	s.eventMu.Unlock()

	go s.runEventListener(ctx, cfg, gen)
}

func (s *Server) runEventListener(ctx context.Context, cfg types.AppConfig, gen uint64) {
	vault := vaultclient.New(cfg.VaultAddress, cfg.PeriodicToken)
	s.state.SetEventStatus(true, nil)
	err := vault.SubscribeEvents(ctx, cfg.SourceNamespace, cfg.EventTopic, cfg.EventFilter, func(event types.VaultEvent) {
		event.ReceivedAt = time.Now().UTC()
		s.state.AddEvent(event, 200)
	})

	if atomic.LoadUint64(&s.eventGen) != gen {
		return
	}

	if ctx.Err() != nil {
		s.state.SetEventStatus(false, nil)
		return
	}

	log.Printf("vault events listener stopped: %v", err)
	s.state.SetEventStatus(false, err)
	if err != nil && (strings.Contains(err.Error(), "got 403") || strings.Contains(strings.ToLower(err.Error()), "permission denied")) {
		log.Printf("vault events listener will not auto-retry after authorization error; update token/policy and save config to restart")
		return
	}
	go func() {
		time.Sleep(5 * time.Second)
		s.ensureEventListener()
	}()
}

func mergeErrors(parts ...[]string) []string {
	result := []string{}
	for _, list := range parts {
		result = append(result, list...)
	}
	sort.Strings(result)
	return result
}

func writeJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
