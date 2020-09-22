// Package kv provides an API client for the Vault KVv1 secrets engine.
//
// To use the default KV secrets engine mounted at "/secret", use the
// DefaultClient:
//
//    // List the KV secret keys at the path "/secret/some/nested/path".
//    kv.DefaultClient.ReadSecret("some/nested/path")
//    kv.ListSecrets("some/nested/path") // shorthand of the above line
//
// To use a kv secrets engine mounted at a custom path, create a new Client:
//
//    // Create a secret at the KV path "/my-kv/some/path".
//    c := kv.NewClient("/my-kv", nil)
//    c.WriteSecret("some/path", map[string]interface{}{"foo": "bar"})
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v1 for more information
// on the available endpoints.
package kv

import (
	"errors"
	"path"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/mwalto7/vault"
)

const defaultMountPath = "/secret"

// DefaultClient is a KVv1 API client mounted at the default path in Vault.
var DefaultClient = NewClient(defaultMountPath, nil)

// ReadSecret reads the secret at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#read-secret.
func ReadSecret(path string) (map[string]interface{}, error) {
	return DefaultClient.ReadSecret(path)
}

// ListSecrets lists the secret keys at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#list-secrets.
func ListSecrets(path string) ([]string, error) {
	return DefaultClient.ListSecrets(path)
}

// WriteSecret creates or updates the secret at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#create-update-secret.
func WriteSecret(path string, data map[string]interface{}) error {
	return DefaultClient.WriteSecret(path, data)
}

// DeleteSecret deletes the secret at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#delete-secret.
func DeleteSecret(path string) error {
	return DefaultClient.DeleteSecret(path)
}

// Client is an API client for the Vault KVv1 secrets engine.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v1#kv-secrets-engine-version-1-api.
type Client struct {
	mountPath string
	client    vault.LogicalClient
}

// NewClient creates a new KVv1 API client for the secrets engine mounted
// at the given path in Vault.
func NewClient(path string, client vault.LogicalClient) *Client {
	return &Client{mountPath: path, client: client}
}

// ReadSecret reads the secret at the specified path.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#read-secret.
func (c *Client) ReadSecret(path string) (map[string]interface{}, error) {
	path, err := c.secretPath(path)
	if err != nil {
		return nil, err
	}
	client, err := c.vaultClient()
	if err != nil {
		return nil, err
	}
	secret, err := client.Read(path)
	if err != nil {
		return nil, err
	}
	if secret == nil || len(secret.Data) == 0 {
		return nil, nil
	}
	return secret.Data, nil
}

// ListSecrets lists the secret keys at the specified path.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#list-secrets.
func (c *Client) ListSecrets(path string) ([]string, error) {
	path, err := c.secretPath(path)
	if err != nil {
		return nil, err
	}
	client, err := c.vaultClient()
	if err != nil {
		return nil, err
	}
	secret, err := client.List(path)
	if err != nil {
		return nil, err
	}
	if secret == nil || len(secret.Data) == 0 {
		return nil, nil
	}
	var aux struct {
		Keys []string `mapstructure:"keys"`
	}
	if err := mapstructure.Decode(secret.Data, &aux); err != nil {
		return nil, err
	}
	return aux.Keys, nil
}

// WriteSecret creates or updates the secret at the specified path.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#create-update-secret.
func (c *Client) WriteSecret(path string, data map[string]interface{}) error {
	path, err := c.secretPath(path)
	if err != nil {
		return err
	}
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	_, err = client.Write(path, data)
	return err
}

// DeleteSecret deletes the secret at the specified path.
//
// See https://www.vaultproject.io/api/secret/kv/kv-v1#delete-secret.
func (c *Client) DeleteSecret(path string) error {
	path, err := c.secretPath(path)
	if err != nil {
		return err
	}
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	_, err = client.Delete(path)
	return err
}

var pathJoin = path.Join

func (c *Client) secretPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("vault: secret path is empty")
	}
	if c.mountPath == "" {
		c.mountPath = defaultMountPath
	}
	return pathJoin(c.mountPath, path), nil
}

func (c *Client) vaultClient() (vault.LogicalClient, error) {
	if c.client != nil {
		return c.client, nil
	}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	c.client = client.Logical()
	return c.client, nil
}
