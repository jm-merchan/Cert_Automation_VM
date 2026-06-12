package vaultclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/coder/websocket"

	"vault-secret-inventory/internal/types"
)

func (c *Client) SubscribeEvents(
	ctx context.Context,
	namespace string,
	topic string,
	filter string,
	onEvent func(types.VaultEvent),
) error {
	if strings.TrimSpace(topic) == "" {
		topic = "kv*"
	}

	apiClient, err := c.newAPIClient(namespace)
	if err != nil {
		return err
	}

	req := apiClient.NewRequest(http.MethodGet, "/v1/sys/events/subscribe/"+strings.TrimSpace(topic))
	u := req.URL
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else {
		u.Scheme = "wss"
	}
	q := u.Query()
	q.Set("json", "true")
	if strings.TrimSpace(filter) != "" {
		q.Set("filter", strings.TrimSpace(filter))
	}
	u.RawQuery = q.Encode()

	apiClient.AddHeader("X-Vault-Token", apiClient.Token())
	apiClient.AddHeader("X-Vault-Namespace", apiClient.Namespace())

	url := u.String()
	var conn *websocket.Conn
	for attempt := 0; attempt < 10; attempt++ {
		respConn, resp, dialErr := websocket.Dial(ctx, url, &websocket.DialOptions{
			HTTPClient: apiClient.CloneConfig().HttpClient,
			HTTPHeader: apiClient.Headers(),
		})
		if dialErr == nil {
			conn = respConn
			break
		}
		if resp == nil {
			return fmt.Errorf("subscribe events websocket dial failed: %w", dialErr)
		}
		if resp.StatusCode == http.StatusTemporaryRedirect {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			if location == "" {
				return fmt.Errorf("subscribe events websocket redirect without location: %w", dialErr)
			}
			url = location
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("events endpoint not found; check Vault events feature availability")
		}
		return fmt.Errorf("subscribe events websocket dial failed (status %d): %w", resp.StatusCode, dialErr)
	}
	if conn == nil {
		return fmt.Errorf("subscribe events websocket dial failed: too many redirects")
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	for {
		_, message, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("events stream closed: %w", err)
		}
		evt := parseVaultEvent(message)
		onEvent(evt)
	}
}

func parseVaultEvent(message []byte) types.VaultEvent {
	raw := map[string]interface{}{}
	if err := json.Unmarshal(message, &raw); err != nil {
		return types.VaultEvent{Raw: map[string]interface{}{"raw": string(message)}}
	}
	evt := types.VaultEvent{Raw: raw}

	if ns, ok := findString(raw, "namespace", "metadata", "namespace"); ok {
		evt.Namespace = ns
	}
	if typ, ok := findString(raw, "event_type", "type"); ok {
		evt.EventType = typ
	}

	if data, ok := raw["data"].(map[string]interface{}); ok {
		if evt.Namespace == "" {
			if ns, ok := findString(data, "namespace"); ok {
				evt.Namespace = ns
			}
		}
		if evt.EventType == "" || evt.EventType == "*" {
			if typ, ok := findString(data, "event_type"); ok {
				evt.EventType = typ
			}
		}
	}
	return evt
}

func findString(raw map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if s, sok := value.(string); sok {
				return s, true
			}
		}
	}
	meta, ok := raw["metadata"].(map[string]interface{})
	if !ok {
		return "", false
	}
	for _, key := range keys {
		if value, exists := meta[key]; exists {
			if s, sok := value.(string); sok {
				return s, true
			}
		}
	}
	return "", false
}
