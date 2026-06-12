package vaultclient

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type MountInfo struct {
	Path      string
	KVVersion int
}

type Client struct {
	address string
	token   string
}

func New(address, token string) *Client {
	return &Client{address: strings.TrimSpace(address), token: strings.TrimSpace(token)}
}

func (c *Client) newAPIClient(namespace string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = c.address
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(c.token)
	client.SetNamespace(strings.TrimSpace(namespace))
	return client, nil
}

func (c *Client) RenewPeriodicToken(ctx context.Context, namespace string) error {
	client, err := c.newAPIClient(namespace)
	if err != nil {
		return err
	}
	_, err = client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("token renew failed: %w", err)
	}
	return nil
}

func (c *Client) ListNamespaces(ctx context.Context, sourceNamespace string) ([]string, error) {
	root := strings.Trim(strings.TrimSpace(sourceNamespace), "/")
	if root == "" {
		root = ""
	}
	seen := map[string]bool{}
	result := []string{}

	var walk func(string) error
	walk = func(parent string) error {
		normParent := strings.Trim(parent, "/")
		if !seen[normParent] {
			seen[normParent] = true
			result = append(result, normParent)
		}

		children, err := c.listNamespaceChildren(ctx, normParent)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unsupported path") {
				return nil
			}
			return err
		}
		for _, child := range children {
			next := child
			if normParent != "" {
				next = normParent + "/" + child
			}
			if err := walk(next); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root); err != nil {
		return nil, err
	}

	sort.Strings(result)
	return result, nil
}

func (c *Client) listNamespaceChildren(ctx context.Context, parent string) ([]string, error) {
	client, err := c.newAPIClient(parent)
	if err != nil {
		return nil, err
	}
	secret, err := client.Logical().ListWithContext(ctx, "sys/namespaces")
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	raw, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}
	keys := []string{}
	for _, item := range toStringSlice(raw) {
		name := strings.TrimSuffix(fmt.Sprintf("%v", item), "/")
		if name == "" {
			continue
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys, nil
}

func (c *Client) ListKVMounts(ctx context.Context, namespace string) ([]MountInfo, error) {
	client, err := c.newAPIClient(namespace)
	if err != nil {
		return nil, err
	}
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	result := []MountInfo{}
	for path, info := range mounts {
		if info == nil || info.Type != "kv" {
			continue
		}
		version := 1
		if info.Options != nil && info.Options["version"] == "2" {
			version = 2
		}
		result = append(result, MountInfo{Path: path, KVVersion: version})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Path < result[j].Path
	})
	return result, nil
}

func (c *Client) ListKVKeys(ctx context.Context, namespace, mount string, kvVersion int, prefix string) ([]string, error) {
	client, err := c.newAPIClient(namespace)
	if err != nil {
		return nil, err
	}
	path := mount
	if kvVersion == 2 {
		path += "metadata/"
	}
	path += strings.TrimPrefix(prefix, "/")
	secret, err := client.Logical().ListWithContext(ctx, path)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported path") || strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			return nil, nil
		}
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	raw, ok := secret.Data["keys"]
	if !ok || raw == nil {
		return nil, nil
	}
	keys := []string{}
	for _, item := range toStringSlice(raw) {
		keys = append(keys, fmt.Sprintf("%v", item))
	}
	sort.Strings(keys)
	return keys, nil
}

func toStringSlice(raw interface{}) []string {
	out := []string{}
	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			out = append(out, fmt.Sprintf("%v", item))
		}
	case []string:
		out = append(out, v...)
	default:
		if raw != nil {
			out = append(out, fmt.Sprintf("%v", raw))
		}
	}
	return out
}

func (c *Client) ReadKVMetadata(ctx context.Context, namespace, mount, secretPath string, kvVersion int) (map[string]interface{}, error) {
	client, err := c.newAPIClient(namespace)
	if err != nil {
		return nil, err
	}
	path := mount + strings.TrimPrefix(secretPath, "/")
	if kvVersion == 2 {
		path = mount + "metadata/" + strings.TrimPrefix(secretPath, "/")
	}
	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return map[string]interface{}{}, nil
	}
	if kvVersion == 2 {
		return secret.Data, nil
	}
	updated := time.Now().UTC().Format(time.RFC3339)
	return map[string]interface{}{
		"updated_time":    updated,
		"created_time":    updated,
		"custom_metadata": map[string]string{},
		"current_version": 1,
	}, nil
}
