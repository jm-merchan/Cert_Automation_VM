package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vault-secret-inventory/internal/types"
)

type Service struct {
	httpClient *http.Client
}

func New() *Service {
	return &Service{httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Service) NotifyWebhook(ctx context.Context, webhookURL string, alerts []types.Alert) error {
	if strings.TrimSpace(webhookURL) == "" || len(alerts) == 0 {
		return nil
	}
	payload := map[string]interface{}{
		"event":        "vault_secret_stale_alert",
		"generated_at": time.Now().UTC(),
		"total_alerts": len(alerts),
		"alerts":       alerts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
