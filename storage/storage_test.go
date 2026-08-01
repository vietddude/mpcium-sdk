package storage

import (
	"errors"
	"testing"
)

func TestShareRotationValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rotation ShareRotation
		wantErr  bool
	}{
		{name: "replacement", rotation: ShareRotation{Replacement: []byte("share")}},
		{name: "retire", rotation: ShareRotation{Retire: true}},
		{name: "empty", rotation: ShareRotation{}, wantErr: true},
		{name: "both", rotation: ShareRotation{Replacement: []byte("share"), Retire: true}, wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.rotation.Validate()
			if tt.wantErr && !errors.Is(err, ErrInvalidShareRotation) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidShareRotation)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error = %v", err)
			}
		})
	}
}
