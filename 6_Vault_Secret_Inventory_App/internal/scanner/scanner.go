package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"vault-secret-inventory/internal/types"
	"vault-secret-inventory/internal/vaultclient"
)

type Service struct {
	vault *vaultclient.Client
}

func New(vault *vaultclient.Client) *Service {
	return &Service{vault: vault}
}

func (s *Service) Scan(ctx context.Context, cfg types.AppConfig) (types.ScanResult, error) {
	cfg.ApplyDefaults()
	start := time.Now().UTC()
	result := types.ScanResult{StartedAt: start}

	if err := s.vault.RenewPeriodicToken(ctx, cfg.SourceNamespace); err != nil {
		result.ScanErrors = append(result.ScanErrors, err.Error())
	}

	namespaces, err := s.vault.ListNamespaces(ctx, cfg.SourceNamespace)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission denied") || strings.Contains(err.Error(), "Code: 403") {
			fallback := strings.Trim(strings.TrimSpace(cfg.SourceNamespace), "/")
			if fallback == "" {
				fallback = ""
			}
			namespaces = []string{fallback}
			result.ScanErrors = append(result.ScanErrors, fmt.Sprintf("namespace listing denied, fallback to source namespace: %s", fallback))
		} else {
			return result, fmt.Errorf("list namespaces failed: %w", err)
		}
	}
	result.Namespaces = namespaces

	records := []types.SecretRecord{}
	scanErrors := []string{}

	for _, ns := range namespaces {
		mounts, err := s.vault.ListKVMounts(ctx, ns)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("namespace=%s list mounts: %v", ns, err))
			continue
		}
		for _, mount := range mounts {
			secretPaths, err := s.walkKV(ctx, ns, mount.Path, mount.KVVersion, "")
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("namespace=%s mount=%s walk: %v", ns, mount.Path, err))
				continue
			}
			for _, secretPath := range secretPaths {
				metadata, err := s.vault.ReadKVMetadata(ctx, ns, mount.Path, secretPath, mount.KVVersion)
				if err != nil {
					scanErrors = append(scanErrors, fmt.Sprintf("namespace=%s mount=%s secret=%s metadata: %v", ns, mount.Path, secretPath, err))
					continue
				}
				records = append(records, s.buildRecord(cfg, ns, mount.Path, secretPath, mount.KVVersion, metadata))
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Namespace != records[j].Namespace {
			return records[i].Namespace < records[j].Namespace
		}
		if records[i].Mount != records[j].Mount {
			return records[i].Mount < records[j].Mount
		}
		return records[i].SecretPath < records[j].SecretPath
	})

	alerts := BuildAlerts(records, cfg.RedThresholdMinutes)
	result.Secrets = records
	result.ScanErrors = append(result.ScanErrors, scanErrors...)
	result.Alerts = alerts
	result.CompletedAt = time.Now().UTC()
	return result, nil
}

func BuildAlerts(records []types.SecretRecord, redThreshold int) []types.Alert {
	alerts := []types.Alert{}
	now := time.Now().UTC()
	for _, record := range records {
		if record.AgeMinutes >= int64(redThreshold) {
			alerts = append(alerts, types.Alert{
				Rule:       "secret_age_exceeded",
				Triggered:  now,
				ThresholdM: redThreshold,
				Secret:     record,
			})
		}
	}
	return alerts
}

func (s *Service) walkKV(ctx context.Context, namespace, mount string, kvVersion int, prefix string) ([]string, error) {
	keys, err := s.vault.ListKVKeys(ctx, namespace, mount, kvVersion, prefix)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, key := range keys {
		if strings.HasSuffix(key, "/") {
			nextPrefix := prefix + key
			nested, err := s.walkKV(ctx, namespace, mount, kvVersion, nextPrefix)
			if err != nil {
				return nil, err
			}
			paths = append(paths, nested...)
			continue
		}
		paths = append(paths, prefix+key)
	}
	return paths, nil
}

func (s *Service) buildRecord(cfg types.AppConfig, namespace, mount, secretPath string, kvVersion int, metadata map[string]interface{}) types.SecretRecord {
	now := time.Now().UTC()
	record := types.SecretRecord{
		Namespace:      namespace,
		Mount:          mount,
		SecretPath:     strings.TrimPrefix(secretPath, "/"),
		KVVersion:      kvVersion,
		Severity:       "green",
		CurrentVersion: 1,
		RawMetadata:    metadata,
	}

	if created, ok := metadata["created_time"].(string); ok && created != "" {
		if parsed, err := time.Parse(time.RFC3339, created); err == nil {
			record.CreatedTime = &parsed
		}
	}
	if updated, ok := metadata["updated_time"].(string); ok && updated != "" {
		if parsed, err := time.Parse(time.RFC3339, updated); err == nil {
			record.UpdatedTime = &parsed
			record.AgeMinutes = int64(now.Sub(parsed).Minutes())
		}
	}
	if record.UpdatedTime == nil && record.CreatedTime != nil {
		record.AgeMinutes = int64(now.Sub(*record.CreatedTime).Minutes())
	}

	if cv, ok := metadata["current_version"].(int); ok {
		record.CurrentVersion = cv
	}
	if cvf, ok := metadata["current_version"].(float64); ok {
		record.CurrentVersion = int(cvf)
	}

	record.CustomMetadata = map[string]string{}
	if cmd, ok := metadata["custom_metadata"].(map[string]interface{}); ok {
		for k, v := range cmd {
			record.CustomMetadata[k] = fmt.Sprintf("%v", v)
		}
	}
	if cms, ok := metadata["custom_metadata"].(map[string]string); ok {
		for k, v := range cms {
			record.CustomMetadata[k] = v
		}
	}

	if record.AgeMinutes >= int64(cfg.RedThresholdMinutes) {
		record.Severity = "red"
	} else if record.AgeMinutes >= int64(cfg.OrangeThresholdMinutes) {
		record.Severity = "orange"
	}

	return record
}
