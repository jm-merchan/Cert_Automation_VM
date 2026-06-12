package state

import (
	"sync"
	"time"

	"vault-secret-inventory/internal/types"
)

type AppState struct {
	mu         sync.RWMutex
	config     types.AppConfig
	namespaces []string
	secrets    []types.SecretRecord
	alerts     []types.Alert
	events     []types.VaultEvent
	eventErr   string
	eventOn    bool
	lastScan   time.Time
	errors     []string
}

func New(initial types.AppConfig) *AppState {
	initial.ApplyDefaults()
	return &AppState{config: initial}
}

func (s *AppState) GetConfig() types.AppConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *AppState) SetConfig(cfg types.AppConfig) {
	cfg.ApplyDefaults()
	s.mu.Lock()
	s.config = cfg
	s.mu.Unlock()
}

func (s *AppState) SetScan(namespaces []string, secrets []types.SecretRecord, alerts []types.Alert, errs []string, when time.Time) {
	s.mu.Lock()
	s.namespaces = append([]string{}, namespaces...)
	s.secrets = append([]types.SecretRecord{}, secrets...)
	s.alerts = append([]types.Alert{}, alerts...)
	s.errors = append([]string{}, errs...)
	s.lastScan = when
	s.mu.Unlock()
}

func (s *AppState) Snapshot() (types.AppConfig, []string, []types.SecretRecord, []types.Alert, time.Time, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config,
		append([]string{}, s.namespaces...),
		append([]types.SecretRecord{}, s.secrets...),
		append([]types.Alert{}, s.alerts...),
		s.lastScan,
		append([]string{}, s.errors...)
}

func (s *AppState) AddEvent(event types.VaultEvent, max int) {
	if max <= 0 {
		max = 200
	}
	s.mu.Lock()
	s.events = append([]types.VaultEvent{event}, s.events...)
	if len(s.events) > max {
		s.events = s.events[:max]
	}
	s.mu.Unlock()
}

func (s *AppState) SetEventStatus(on bool, err error) {
	s.mu.Lock()
	s.eventOn = on
	if err != nil {
		s.eventErr = err.Error()
	} else {
		s.eventErr = ""
	}
	s.mu.Unlock()
}

func (s *AppState) EventsSnapshot() ([]types.VaultEvent, bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]types.VaultEvent{}, s.events...), s.eventOn, s.eventErr
}
