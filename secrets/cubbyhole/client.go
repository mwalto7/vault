// Package cubbyhole provides an API client for the Vault Cubbyhole secrets engine.
//
// To use the default Cubbyhole secrets engine mounted at "/cubbyhole", use the
// DefaultClient:
//
//    // List the Cubbyhole secret keys at the path "/cubbyhole/some/nested/path".
//    cubbyhole.DefaultClient.ReadSecret("some/nested/path")
//    cubbyhole.ListSecrets("some/nested/path") // shorthand of the above line
//
// To use a Cubbyhole secrets engine mounted at a custom path, create a new Client:
//
//    // Create a secret at the Cubbyhole path "/my-cubbyhole/some/path".
//    c := cubbyhole.NewClient("/my-cubbyhole", nil)
//    c.WriteSecret("some/path", map[string]interface{}{"foo": "bar"})
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole for more
// information on the available endpoints.
package cubbyhole

import (
	"errors"
	"os"
	"path"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/mwalto7/vault"
)

const defaultMountPath = "/cubbyhole"

var (
	// ErrEmptyPath is returned when the secret path is an empty string.
	ErrEmptyPath = errors.New("cubbyhole: path is empty")

	// ErrNoSecretData is returned when no data is stored at the secret path.
	ErrNoSecretData = errors.New("cubbyhole: no secret data")
)

// DefaultClient is a Cubbyhole API client mounted at the default path in Vault.
var DefaultClient = NewClient(defaultMountPath, nil)

// ReadSecret reads the secret at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#read-secret.
func ReadSecret(path string) (map[string]interface{}, error) {
	return DefaultClient.ReadSecret(path)
}

// ListSecrets lists the secret keys at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#list-secrets.
func ListSecrets(path string) ([]string, error) {
	return DefaultClient.ListSecrets(path)
}

// WriteSecret creates or updates the secret at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#create-update-secret.
func WriteSecret(path string, data map[string]interface{}) error {
	return DefaultClient.WriteSecret(path, data)
}

// DeleteSecret deletes the secret at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#delete-secret.
func DeleteSecret(path string) error {
	return DefaultClient.DeleteSecret(path)
}

// Client is an API client for the Vault Cubbyhole secrets engine.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#cubbyhole-secrets-engine-api.
type Client struct {
	mountPath string
	client    vault.LogicalClient
}

// NewClient creates a new Cubbyhole API client for the secrets engine mounted
// at the given path in Vault.
func NewClient(path string, client vault.LogicalClient) *Client {
	return &Client{mountPath: path, client: client}
}

// ReadSecret reads the secret at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#read-secret.
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
		return nil, &os.PathError{Op: "ReadSecret", Path: path, Err: ErrNoSecretData}
	}
	return secret.Data, nil
}

// ListSecrets lists the secret keys at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#list-secrets.
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
		return nil, &os.PathError{Op: "ListSecrets", Path: path, Err: ErrNoSecretData}
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
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#create-update-secret.
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
// See https://www.vaultproject.io/api-docs/secret/cubbyhole#delete-secret.
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
		return "", ErrEmptyPath
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
