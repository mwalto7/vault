// Package kv provides an API client for the Vault KVv2 secrets engine.
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
// vailable
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2 for more information
// on the available endpoints.
package kv

import (
	"encoding/json"
	"errors"
	"path"
	"strconv"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/mwalto7/vault"
)

const defaultMountPath = "/secret"

// DefaultClient is a KVv2 API client mounted at the default path in Vault.
var DefaultClient = NewClient(defaultMountPath, nil)

// SetEngineConfig updates the KVv2 secrets engine configuration using the
// DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#configure-the-kv-engine.
func SetEngineConfig(cfg SecretConfig) error {
	return DefaultClient.SetEngineConfig(cfg)
}

// EngineConfig returns the KVv2 secrets engine configuration using the
// DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-kv-engine-configuration.
func EngineConfig() (SecretConfig, error) {
	return DefaultClient.EngineConfig()
}

// ReadSecretLatest reads the latest secret version at the specified path using
// the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-version.
func ReadSecretLatest(path string) (Secret, error) {
	return DefaultClient.ReadSecretLatest(path)
}

// ReadSecretVersion reads the secret version at the specified path using the
// DefaultClient. If the version is negative, the latest secret version is read.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-version.
func ReadSecretVersion(path string, version int) (Secret, error) {
	return DefaultClient.ReadSecretVersion(path, version)
}

// WriteSecretLatest creates or updates the latest secret version at the
// specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret.
func WriteSecretLatest(path string, data map[string]interface{}) (SecretVersion, error) {
	return DefaultClient.WriteSecretLatest(path, data)
}

// WriteSecretVersion creates or updates a secret version at the specified path
// using the DefaultClient.
//
// If the version is less than zero, all writes are allowed. If the version is
// zero, writes are allowed only if the secret does not already exist. If the
// version is positive, writes are allowed only if the specified version matches
// the current version of the secret.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret.
func WriteSecretVersion(path string, version int, data map[string]interface{}) (SecretVersion, error) {
	return DefaultClient.WriteSecretVersion(path, version, data)
}

// DeleteSecretLatest soft deletes the latest secret version at the specified
// path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-latest-version-of-secret.
func DeleteSecretLatest(path string) error {
	return DefaultClient.DeleteSecretLatest(path)
}

// DeleteSecretVersion soft deletes the secret version(s) at the specified path
// using the DefaultClient. Must specify at least one version.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-secret-versions.
func DeleteSecretVersion(path string, version ...int) error {
	return DefaultClient.DeleteSecretVersion(path, version...)
}

// UndeleteSecretVersion restores the secret version(s) at the specified path
// using the DefaultClient. Must specify at least one version.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#undelete-secret-versions.
func UndeleteSecretVersion(path string, version ...int) error {
	return DefaultClient.UndeleteSecretVersion(path, version...)
}

// DestroySecretVersion permanently deletes the secret version(s) at the
// specified path using the DefaultClient. Must specify at least one version.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#destroy-secret-versions.
func DestroySecretVersion(path string, version ...int) error {
	return DefaultClient.DestroySecretVersion(path, version...)
}

// ListSecrets lists the secret keys at the specified path using the
// DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#list-secrets.
func ListSecrets(path string) ([]string, error) {
	return DefaultClient.ListSecrets(path)
}

// ReadSecretMetadata returns the metadata of the secret at the specified path
// using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-metadata.
func ReadSecretMetadata(path string) (SecretMetadata, error) {
	return DefaultClient.ReadSecretMetadata(path)
}

// WriteSecretMetadata updates the secret configuration at the specified path
// using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#update-metadata.
func WriteSecretMetadata(path string, cfg SecretConfig) error {
	return DefaultClient.WriteSecretMetadata(path, cfg)
}

// DeleteSecretMetadata permanently deletes the secret metadata and all versions
// at the specified path using the DefaultClient.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-metadata-and-all-versions.
func DeleteSecretMetadata(path string) error {
	return DefaultClient.DeleteSecretMetadata(path)
}

// Client is an API client for the Vault KVv2 secrets engine.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#kv-secrets-engine-version-2-api.
type Client struct {
	mountPath string
	client    vault.LogicalClient
}

// NewClient creates a new KVv2 API client for the secrets engine mounted at the
// given path in Vault.
func NewClient(path string, client vault.LogicalClient) *Client {
	return &Client{mountPath: path, client: client}
}

// SecretConfig represents the configurable settings of a secret stored in the
// KVv2 secrets engine. Can be used for global or local secret configuration.
type SecretConfig struct {
	// The maximum allowed number of secret versions to keep.
	MaxVersions int `json:"max_versions,omitempty"`

	// Specifies if CAS is required for a secret.
	CASRequired bool `json:"cas_required,omitempty"`

	// Specified the duration after which to delete secret version(s).
	DeleteVersionAfter time.Duration `json:"delete_version_after,omitempty"`
}

// SetEngineConfig updates the KVv2 secrets engine configuration.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#configure-the-kv-engine.
func (c *Client) SetEngineConfig(cfg SecretConfig) error {
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	_, err = client.Write(pathJoin(c.mountPath, "config"), data)
	return err
}

// EngineConfig returns the KVv2 secrets engine configuration.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-kv-engine-configuration.
func (c *Client) EngineConfig() (SecretConfig, error) {
	client, err := c.vaultClient()
	if err != nil {
		return SecretConfig{}, err
	}
	secret, err := client.Read(pathJoin(c.mountPath, "config"))
	if err != nil {
		return SecretConfig{}, err
	}
	if secret == nil || len(secret.Data) == 0 {
		return SecretConfig{}, nil
	}
	var aux struct {
		Data SecretConfig `mapstructure:"data"`
	}
	if err := mapstructure.Decode(secret.Data, &aux); err != nil {
		return SecretConfig{}, err
	}
	return aux.Data, nil
}

// SecretMetadata represents a secret's data and all of its version metadata.
type SecretMetadata struct {
	// The time at which the secret was created.
	CreatedTime time.Time `json:"created_time"`

	// The latest version of the secret.
	CurrentVersion int `json:"current_version"`

	// The maximum allowed number of secret versions to store.
	MaxVersions int `json:"max_versions"`

	// The oldest available version of the secret.
	OldestVersion int `json:"oldest_version"`

	// The last time at which the secret was updated, or modified.
	UpdatedTime time.Time `json:"updated_time"`

	// The version metadata for all versions of the secret.
	Versions map[string]SecretVersion `json:"versions"`
}

// SecretVersion represents metadata about a specific version of a secret.
type SecretVersion struct {
	// The time at which the secret version was created.
	CreatedTime time.Time `json:"created_time"`

	// The time at which the secret version was deleted (if deleted).
	DeletionTime time.Time `json:"deletion_time"`

	// Specifies if the secret version was destroyed.
	Destroyed bool `json:"destroyed"`

	// The specific version of the secret.
	Version int `json:"version"`
}

// Secret represents a secret's data and its specific version metadata.
type Secret struct {
	// The data stored at the secret path.
	Data map[string]interface{} `json:"data"`

	// The version metadata associated with the secret.
	Metadata SecretVersion `json:"metadata"`
}

// ReadSecretLatest reads the latest secret version at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-version.
func (c *Client) ReadSecretLatest(path string) (Secret, error) {
	return c.ReadSecretVersion(path, -1)
}

// ReadSecretVersion reads the secret version at the specified path. If the
// version is negative, the latest secret version is read.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-version.
func (c *Client) ReadSecretVersion(path string, version int) (Secret, error) {
	path, err := c.secretPath(path, false)
	if err != nil {
		return Secret{}, err
	}
	client, err := c.vaultClient()
	if err != nil {
		return Secret{}, err
	}
	var secret *api.Secret
	if version > -1 {
		v := strconv.Itoa(version)
		secret, err = client.ReadWithData(path, map[string][]string{"version": {v}})
		if err != nil {
			return Secret{}, err
		}
	} else {
		secret, err = client.Read(path)
		if err != nil {
			return Secret{}, err
		}
	}
	if secret == nil || len(secret.Data) == 0 {
		return Secret{}, nil
	}
	var aux struct {
		Data Secret `mapstructure:"data"`
	}
	if err := mapstructure.Decode(secret.Data, &aux); err != nil {
		return Secret{}, err
	}
	return aux.Data, nil
}

// WriteSecretLatest creates or updates the latest secret version at the
// specified path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret.
func (c *Client) WriteSecretLatest(path string, data map[string]interface{}) (SecretVersion, error) {
	return c.WriteSecretVersion(path, -1, data)
}

// WriteSecretVersion creates or updates a secret version at the specified path.
//
// If the version is less than zero, all writes are allowed. If the version is
// zero, writes are allowed only if the secret does not already exist. If the
// version is positive, writes are allowed only if the specified version matches
// the current version of the secret.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret.
func (c *Client) WriteSecretVersion(path string, version int, data map[string]interface{}) (SecretVersion, error) {
	path, err := c.secretPath(path, false)
	if err != nil {
		return SecretVersion{}, err
	}
	client, err := c.vaultClient()
	if err != nil {
		return SecretVersion{}, err
	}
	d := map[string]interface{}{"data": data}
	if version > -1 {
		d["options"] = map[string]interface{}{"cas": version}
	}
	secret, err := client.Write(path, d)
	if err != nil {
		return SecretVersion{}, err
	}
	if secret == nil || len(secret.Data) == 0 {
		return SecretVersion{}, nil
	}
	var aux struct {
		Data SecretVersion `mapstructure:"data"`
	}
	if err := mapstructure.Decode(secret.Data, &aux); err != nil {
		return SecretVersion{}, err
	}
	return aux.Data, nil
}

// DeleteSecretLatest soft deletes the latest secret version at the specified
// path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-latest-version-of-secret.
func (c *Client) DeleteSecretLatest(path string) error {
	path, err := c.secretPath(path, false)
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

// DeleteSecretVersion soft deletes the secret version(s) at the specified path.
// Must specify at least one version.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-secret-versions.
func (c *Client) DeleteSecretVersion(path string, version ...int) error {
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	path = pathJoin(c.mountPath, "delete", path)
	_, err = client.Write(path, map[string]interface{}{"versions": version})
	return err
}

// UndeleteSecretVersion restores the secret version(s) at the specified path.
// Must specify at least one version.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#undelete-secret-versions.
func (c *Client) UndeleteSecretVersion(path string, version ...int) error {
	if len(version) == 0 {
		return errors.New("kv2: must specify at least one version")
	}
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	path = pathJoin(c.mountPath, "undelete", path)
	_, err = client.Write(path, map[string]interface{}{"versions": version})
	return err
}

// DestroySecretVersion permanently deletes the secret version(s) at the
// specified path. Must specify at least one version.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#destroy-secret-versions.
func (c *Client) DestroySecretVersion(path string, version ...int) error {
	if len(version) == 0 {
		return errors.New("kv2: must specify at least one version")
	}
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	path = pathJoin(c.mountPath, "destroy", path)
	_, err = client.Write(path, map[string]interface{}{"versions": version})
	return err
}

// ListSecrets lists the secret keys at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#list-secrets.
func (c *Client) ListSecrets(path string) ([]string, error) {
	path, err := c.secretPath(path, true)
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
		Data struct {
			Keys []string `mapstructure:"keys"`
		} `json:"data"`
	}
	if err := mapstructure.Decode(secret.Data, &aux); err != nil {
		return nil, err
	}
	return aux.Data.Keys, nil
}

// ReadSecretMetadata returns the metadata of the secret at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-metadata.
func (c *Client) ReadSecretMetadata(path string) (SecretMetadata, error) {
	path, err := c.secretPath(path, true)
	if err != nil {
		return SecretMetadata{}, err
	}
	client, err := c.vaultClient()
	if err != nil {
		return SecretMetadata{}, err
	}
	secret, err := client.List(path)
	if err != nil {
		return SecretMetadata{}, err
	}
	if secret == nil || len(secret.Data) == 0 {
		return SecretMetadata{}, nil
	}
	var aux struct {
		Data SecretMetadata `mapstructure:"data"`
	}
	if err := mapstructure.Decode(secret.Data, &aux); err != nil {
		return SecretMetadata{}, err
	}
	return aux.Data, nil
}

// WriteSecretMetadata updates the secret configuration at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#update-metadata.
func (c *Client) WriteSecretMetadata(path string, cfg SecretConfig) error {
	path, err := c.secretPath(path, true)
	if err != nil {
		return err
	}
	client, err := c.vaultClient()
	if err != nil {
		return err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	_, err = client.Write(path, data)
	return err
}

// DeleteSecretMetadata permanently deletes the secret metadata and all versions
// at the specified path.
//
// See https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-metadata-and-all-versions.
func (c *Client) DeleteSecretMetadata(path string) error {
	path, err := c.secretPath(path, true)
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

func (c *Client) secretPath(path string, metadata bool) (string, error) {
	if path == "" {
		return "", errors.New("kv2: secret path is empty")
	}
	if c.mountPath == "" {
		c.mountPath = defaultMountPath
	}
	fields := []string{c.mountPath}
	if metadata {
		fields = append(fields, "metadata")
	} else {
		fields = append(fields, "data")
	}
	return pathJoin(append(fields, path)...), nil
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
