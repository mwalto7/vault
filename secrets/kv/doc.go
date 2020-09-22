// Package kv provides API clients for the Vault KV v1 and v2 secrets engines.
//
// To use the KVv1 secrets engine import package v1:
//
//    import "github.com/mwalto7/vault/secrets/kv/v1"
//
// To use the KVv2 secrets engine import package v2:
//
//    import "github.com/mwalto7/vault/secrets/kv/v2"
//
// If needed, both KV clients can be imported at the same time:
//
//    import (
//        kv1 "github.com/mwalto7/vault/secrets/kv/v1"
//        kv2 "github.com/mwalto7/vault/secrets/kv/v2"
//    )
//
// See https://www.vaultproject.io/api-docs/secret/kv for more information on
// the available endpoints.
package kv
