package types

import "time"

type AppConfig struct {
	VaultAddress           string `json:"vaultAddress"`
	PeriodicToken          string `json:"periodicToken"`
	SourceNamespace        string `json:"sourceNamespace"`
	EventTopic             string `json:"eventTopic"`
	EventFilter            string `json:"eventFilter"`
	OrangeThresholdMinutes int    `json:"orangeThresholdMinutes"`
	RedThresholdMinutes    int    `json:"redThresholdMinutes"`
	WebhookURL             string `json:"webhookUrl"`
	ScanIntervalSeconds    int    `json:"scanIntervalSeconds"`
}

func (c *AppConfig) ApplyDefaults() {
	if c.OrangeThresholdMinutes <= 0 {
		c.OrangeThresholdMinutes = 30
	}
	if c.RedThresholdMinutes <= 0 {
		c.RedThresholdMinutes = 60
	}
	if c.ScanIntervalSeconds <= 0 {
		c.ScanIntervalSeconds = 120
	}
	if c.RedThresholdMinutes < c.OrangeThresholdMinutes {
		c.RedThresholdMinutes = c.OrangeThresholdMinutes
	}
	if c.EventTopic == "" {
		c.EventTopic = "kv*"
	}
}

type VaultEvent struct {
	ReceivedAt time.Time              `json:"receivedAt"`
	Namespace  string                 `json:"namespace,omitempty"`
	EventType  string                 `json:"eventType,omitempty"`
	Raw        map[string]interface{} `json:"raw"`
}

type SecretRecord struct {
	Namespace      string                 `json:"namespace"`
	Mount          string                 `json:"mount"`
	SecretPath     string                 `json:"secretPath"`
	KVVersion      int                    `json:"kvVersion"`
	CreatedTime    *time.Time             `json:"createdTime,omitempty"`
	UpdatedTime    *time.Time             `json:"updatedTime,omitempty"`
	AgeMinutes     int64                  `json:"ageMinutes"`
	Severity       string                 `json:"severity"`
	CurrentVersion int                    `json:"currentVersion"`
	CustomMetadata map[string]string      `json:"customMetadata,omitempty"`
	RawMetadata    map[string]interface{} `json:"rawMetadata,omitempty"`
}

type Alert struct {
	Rule       string       `json:"rule"`
	Triggered  time.Time    `json:"triggeredAt"`
	ThresholdM int          `json:"thresholdMinutes"`
	Secret     SecretRecord `json:"secret"`
}

type ScanResult struct {
	StartedAt     time.Time      `json:"startedAt"`
	CompletedAt   time.Time      `json:"completedAt"`
	Namespaces    []string       `json:"namespaces"`
	Secrets       []SecretRecord `json:"secrets"`
	ScanErrors    []string       `json:"scanErrors"`
	Alerts        []Alert        `json:"alerts"`
	WebhookErrors []string       `json:"webhookErrors"`
}
