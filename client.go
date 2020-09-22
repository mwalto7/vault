package vault

import "github.com/hashicorp/vault/api"

//go:generate mockgen -destination=vaultmock/logical_client.go -package=vaultmock -mock_names=LogicalClient=LogicalClient github.com/mwalto7/vault LogicalClient

// LogicalClient represents a vault/api.Logical client.
//
// See https://github.com/hashicorp/vault/blob/master/api/logical.go#L41.
type LogicalClient interface {
	Read(path string) (*api.Secret, error)
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	List(path string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
	Delete(path string) (*api.Secret, error)
	DeleteWithData(path string, data map[string][]string) (*api.Secret, error)
	Unwrap(wrappingToken string) (*api.Secret, error)
}
