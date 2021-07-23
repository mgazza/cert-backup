// +build integration

package controllers

import (
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"testing"
	"time"
)

func secretFromFile(t *testing.T, f string) *v1.Secret {
	data, err := ioutil.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	result := &v1.Secret{}
	err = json.Unmarshal(data, result)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func Test_verifySecret(t *testing.T) {

	tests := []struct {
		name    string
		secret  *v1.Secret
		want    bool
		wantErr bool
		now     time.Time
	}{
		{
			name:   "valid cert",
			secret: secretFromFile(t, "valid.json"),
			want:   true,
			now:    time.Date(2021, 8, 1, 0, 0, 0, 0, time.Local),
		}, {
			name:   "valid cert before its 'valid'",
			secret: secretFromFile(t, "valid2.json"),
			now:    time.Date(2021, 5, 1, 0, 0, 0, 0, time.Local),
			want:   false,
		},
		{
			name:   "invalid cert",
			secret: secretFromFile(t, "invalid.json"),
			now:    time.Date(2021, 7, 21, 0, 0, 0, 0, time.Local),
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			oldnow := now
			defer func() {
				now = oldnow
			}()
			now = func() time.Time {
				return tt.now
			}

			got, err := verifySecret(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifySecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("verifySecret() got = %v, want %v", got, tt.want)
			}
		})
	}
}
