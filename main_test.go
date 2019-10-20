/*
Copyright 2019 Philippe Pepiot <phil@philpep.org>


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDigestURL(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"r.philpep.org/nginx", "https://r.philpep.org/v2/nginx/manifests/latest"},
		{"r.philpep.org/nginx:3.4", "https://r.philpep.org/v2/nginx/manifests/3.4"},
		{"quay.io/calico/cni:v3.4.0", "https://quay.io/v2/calico/cni/manifests/v3.4.0"},
		{"nginx:alpine", "https://docker.io/v2/library/nginx/manifests/alpine"},
		{"nginx", "https://docker.io/v2/library/nginx/manifests/latest"},
		{"index.docker.io/library/nginx", "https://docker.io/v2/library/nginx/manifests/latest"},
		{"calico/node:v2.3", "https://docker.io/v2/calico/node/manifests/v2.3"},
		{"registry:5000/nginx", "https://registry:5000/v2/nginx/manifests/latest"},
		{"registry:5000/nginx:alpine", "https://registry:5000/v2/nginx/manifests/alpine"},
		{"registry:5000/user/nginx:alpine", "https://registry:5000/v2/user/nginx/manifests/alpine"},
	}
	for _, test := range tests {
		url, err := getDigestURL(test.name)
		assert.Nil(t, err)
		assert.Equal(t, url, test.expected)
	}
}

func TestGetDigest(t *testing.T) {
	expected := map[string]string{
		"image":   "sha256:c166da3ccff505a36b4bfef93d29f102258073f1a784e2af00b1b001b5c1b3c3",
		"image:1": "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
		"image:2": "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/image/manifests/latest":
			w.Header().Set("Docker-Content-Digest", expected["image"])
		case "/v2/image/manifests/1":
			authorization := r.Header.Get("Authorization")
			if authorization == "" {
				w.Header().Set("www-authenticate", fmt.Sprintf(
					"Bearer realm=\"https://%s/token\",service=\"srv\",scope=\"repository:nginx/nginx:pull\"", r.Host))
				w.WriteHeader(401)
			} else {
				assert.Equal(t, authorization, "Bearer secret")
				w.Header().Set("Docker-Content-Digest", expected["image:1"])
			}
		case "/token":
			if _, err := io.WriteString(w, `{"token": "secret"}`); err != nil {
				panic(err.Error())
			}
		case "/v2/image/manifests/2":
			username, password, _ := r.BasicAuth()
			assert.Equal(t, username, "user")
			assert.Equal(t, password, "pass")
			w.Header().Set("Docker-Content-Digest", expected["image:2"])
		default:
			t.Errorf("Unexpected request URL %s", r.URL)
		}
	}))
	defer ts.Close()
	reg := NewRegistryClient(ts.Client())
	host, err := url.Parse(ts.URL)
	assert.Nil(t, err)
	assertDigest := func(name string) {
		digest, err := reg.GetDigest(fmt.Sprintf("%s/%s", host.Host, name))
		assert.Nil(t, err)
		assert.Equal(t, digest, expected[name])
	}
	assertDigest("image")
	assertDigest("image:1")
	reg.Auth = map[string]string{host.Host: "dXNlcjpwYXNz"}
	assertDigest("image:2")
}
