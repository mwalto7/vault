package cubbyhole_test

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/api"
	"github.com/mwalto7/vault/secrets/cubbyhole"
	"github.com/mwalto7/vault/vaultmock"
)

func TestClient_ReadSecret(t *testing.T) {
	tt := []struct {
		name string
		path string
		data map[string]interface{}
		err  error
	}{
		{
			name: "ErrEmptyPath",
			path: "",
			data: nil,
			err:  cubbyhole.ErrEmptyPath,
		},
		{
			name: "ErrReadPath",
			path: "test",
			data: nil,
			err:  errors.New("error"),
		},
		{
			name: "ErrNoSecretData",
			path: "test",
			data: nil,
			err:  nil,
		},
		{
			name: "OK",
			path: "test",
			data: map[string]interface{}{"foo": "bar"},
			err:  nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			m := vaultmock.NewLogicalClient(gomock.NewController(t))
			expect := m.EXPECT().Read("/cubbyhole/" + tc.path)
			if tc.err != nil {
				expect.Return(nil, tc.err)
			} else {
				expect.Return(&api.Secret{Data: tc.data}, nil)
			}

			data, err := cubbyhole.NewClient("", m).ReadSecret(tc.path)

			var pathErr *os.PathError
			if err != nil && errors.As(err, &pathErr) {
				if want := cubbyhole.ErrNoSecretData; !errors.Is(pathErr, want) {
					t.Fatalf("err: got %v, want %v", pathErr, want)
				}
				return
			}

			if !errors.Is(err, tc.err) {
				t.Fatalf("err: got %v, want %v", err, tc.err)
			}
			if !reflect.DeepEqual(data, tc.data) {
				t.Fatalf("data: got %v, want %v", data, tc.data)
			}
		})
	}
}
