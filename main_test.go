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
	"testing"
)

func TestGetDigestURL(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"r.philpep.org/nginx", "https://r.philpep.org/v2/nginx/manifests/latest"},
		{"r.philpep.org/nginx:3.4", "https://r.philpep.org/v2/nginx/manifests/3.4"},
		{"quay.io/calico/cni:v3.4.0", "https://quay.io/v2/calico/cni/manifests/v3.4.0"},
		{"nginx:alpine", "https://registry.hub.docker.com/v2/library/nginx/manifests/alpine"},
		{"calico/node:v2.3", "https://registry.hub.docker.com/v2/calico/node/manifests/v2.3"},
		{"registry:5000/nginx", "https://registry:5000/v2/nginx/manifests/latest"},
		{"registry:5000/nginx:alpine", "https://registry:5000/v2/nginx/manifests/alpine"},
		{"registry:5000/user/nginx:alpine", "https://registry:5000/v2/user/nginx/manifests/alpine"},
	}
	for _, test := range tests {
		digestURL := getDigestURL(test.name)
		if digestURL != test.expected {
			t.Errorf("getDigestURL(%s) = %s, expected %s",
				test.name, digestURL, test.expected)
		}
	}
}
