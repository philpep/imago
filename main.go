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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

func closeResource(r io.Closer) {
	err := r.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func getDigestURL(name string) string {
	u, err := url.Parse(fmt.Sprintf("https://%s", name))
	if err != nil {
		log.Fatal(err)
	}
	host := u.Host
	path := u.Path
	tag := "latest"
	if host == name || (!strings.Contains(host, ".") && !strings.Contains(host, ":")) {
		host = "registry.hub.docker.com"
		if !strings.Contains(path, "/") {
			path = "/library/" + name
		} else {
			path = "/" + name
		}
	}
	if strings.Contains(path, ":") {
		s := strings.Split(path, ":")
		path, tag = s[0], s[1]
	}
	return fmt.Sprintf("%s://%s/v2%s/manifests/%s", u.Scheme, host, path, tag)
}

func getBearerToken(client *http.Client, authHeader string) string {
	r := regexp.MustCompile("(.*)=\"(.*)\"")
	authInfo := make(map[string]string)
	for _, part := range strings.Split(strings.Split(authHeader, " ")[1], ",") {
		match := r.FindStringSubmatch(part)
		authInfo[match[1]] = match[2]
	}
	if authInfo["realm"] == "" || authInfo["service"] == "" || authInfo["scope"] == "" {
		log.Fatalf("Unexpected or missing auth headers: %s", authInfo)
	}
	req, err := http.NewRequest("GET", authInfo["realm"], nil)
	if err != nil {
		log.Fatal(err)
	}
	q := req.URL.Query()
	q.Add("service", authInfo["service"])
	q.Add("scope", authInfo["scope"])
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer closeResource(resp.Body)
	if resp.StatusCode != 200 {
		log.Fatalf("Error while requesting auth token on %s: %s", req.URL, resp.Status)
	}
	var result struct {
		Token string `json:"token"`
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Fatal(err)
	}
	return result.Token
}

// RegistryClient represent a docker client
type RegistryClient struct {
	client *http.Client
	Auth   map[string]string
	cache  map[string]string
}

// NewRegistryClient initialize a RegistryClient
func NewRegistryClient(client *http.Client) *RegistryClient {
	if client == nil {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}
	return &RegistryClient{
		client: client,
		Auth:   make(map[string]string),
		cache:  make(map[string]string)}
}

// GetDigest return the docker digest of given image name
func (c *RegistryClient) GetDigest(name string) string {
	digestURL := getDigestURL(name)
	req, err := http.NewRequest("HEAD", digestURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	u, err := url.Parse(digestURL)
	if err != nil {
		log.Fatal(err)
	}
	if c.Auth[u.Host] != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", c.Auth[u.Host]))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer closeResource(resp.Body)
	authenticate := resp.Header.Get("www-authenticate")
	if resp.StatusCode == 401 && strings.HasPrefix(authenticate, "Bearer ") {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", getBearerToken(c.client, authenticate)))
		resp, err = c.client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer closeResource(resp.Body)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("Unexpected response while requesting %s: %s", digestURL, resp.Status)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		log.Fatalf("No Docker-Content-Digest in response headers for %s", digestURL)
	}
	return digest
}

type parentController struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	ObjectMeta metav1.ObjectMeta `json:"metadata"`
	Spec       struct {
		Template struct {
			Spec v1.PodSpec
		} `json:"template"`
	} `json:"spec"`
}

// Config represent a imago configuration
type Config struct {
	cluster     *kubernetes.Clientset
	reg         *RegistryClient
	pods        *v1.PodList
	replicasets *appsv1.ReplicaSetList
	secretCache map[string]*v1.Secret
	namespace   string
	dryrun      bool
}

// NewConfig initialize a new imago config
func NewConfig(kubeconfig string, namespace string, allnamespaces bool, dryrun bool) *Config {
	c := &Config{reg: NewRegistryClient(nil), dryrun: dryrun}
	var err error
	var clusterConfig *rest.Config

	setNamespace := func(incluster bool) {
		if allnamespaces {
			c.namespace = ""
		} else if namespace != "" {
			c.namespace = namespace
		} else {
			if incluster {
				c.namespace = inClusterNamespace()
			} else {
				c.namespace = outClusterNamespace(kubeconfig)
			}
			if c.namespace == "" {
				log.Fatal("Could not determine current namespace")
			}
		}
	}

	if inClusterClientPossible() {
		clusterConfig, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
		setNamespace(true)
	} else {
		clusterConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatal(err)
		}
		setNamespace(false)
	}
	c.cluster, err = kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		log.Fatal(err)
	}
	return c
}

// Update Deployment and DaemonSet matching given selectors
func (c *Config) Update(fieldSelector, labelSelector string) {
	client := c.cluster.AppsV1()
	opts := metav1.ListOptions{FieldSelector: fieldSelector, LabelSelector: labelSelector}
	deployments, err := client.Deployments(c.namespace).List(opts)
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range deployments.Items {
		images := c.getNewImages("Deployment", &d.ObjectMeta, &d.Spec.Template.Spec)
		c.setImage(d.ObjectMeta.Namespace, "Deployment", d.ObjectMeta.Name, images)
	}
	daemonsets, err := client.DaemonSets(c.namespace).List(opts)
	if err != nil {
		log.Fatal(err)
	}
	for _, ds := range daemonsets.Items {
		images := c.getNewImages("DaemonSet", &ds.ObjectMeta, &ds.Spec.Template.Spec)
		c.setImage(ds.ObjectMeta.Namespace, "DaemonSet", ds.ObjectMeta.Name, images)
	}
}

func (c *Config) getPods() *v1.PodList {
	if c.pods == nil {
		var err error
		c.pods, err = c.cluster.CoreV1().Pods(c.namespace).List(metav1.ListOptions{FieldSelector: "status.phase=Running"})
		if err != nil {
			log.Fatal(err)
		}
	}
	return c.pods
}

func (c *Config) getReplicaSets() *appsv1.ReplicaSetList {
	if c.replicasets == nil {
		var err error
		c.replicasets, err = c.cluster.AppsV1().ReplicaSets(c.namespace).List(metav1.ListOptions{})
		if err != nil {
			log.Fatal(err)
		}
	}
	return c.replicasets
}

func (c *Config) getSecret(namespace string, name string) *v1.Secret {
	key := fmt.Sprintf("%s/%s", namespace, name)
	if c.secretCache == nil {
		c.secretCache = make(map[string]*v1.Secret)
	}
	if c.secretCache[key] == nil {
		secret, err := c.cluster.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			log.Fatal(err)
		}
		c.secretCache[key] = secret
	}
	return c.secretCache[key]
}

func (c *Config) setRegistryCredentials(namespace string, secrets []v1.LocalObjectReference) {
	c.reg.Auth = make(map[string]string)
	var dockerconfig struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	for _, secret := range secrets {
		err := json.Unmarshal(c.getSecret(namespace, secret.Name).Data[v1.DockerConfigJsonKey],
			&dockerconfig)
		if err != nil {
			log.Fatal(err)
		}
		for host, auth := range dockerconfig.Auths {
			c.reg.Auth[host] = auth.Auth
		}
	}
}

func (c *Config) getNewImages(kind string, meta *metav1.ObjectMeta, spec *v1.PodSpec) map[string]string {
	log.Printf("checking %s/%s:", kind, meta.Name)
	result := make(map[string]string)
	c.setRegistryCredentials(meta.Namespace, spec.ImagePullSecrets)
	lastAppliedConfig := meta.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	if len(lastAppliedConfig) == 0 {
		log.Printf("  no %s annotation, skipping", v1.LastAppliedConfigAnnotation)
		return result
	}
	var obj parentController
	err := json.Unmarshal([]byte(lastAppliedConfig), &obj)
	if err != nil {
		log.Fatal(err)
	}
	sha256Re := regexp.MustCompile("docker-pullable://.*@(sha256:.*)")
	runningImages := c.getRunningImagesFor(&obj)
	if len(runningImages) == 0 {
		log.Printf("  no running pod found (rolling update in progress ?)")
		return result
	}
	for _, specContainer := range obj.Spec.Template.Spec.Containers {
		for container, running := range runningImages {
			if specContainer.Name != container {
				continue
			}
			digest := c.reg.GetDigest(specContainer.Image)
			runningDigest := sha256Re.FindStringSubmatch(running)[1]
			if digest != runningDigest {
				result[container] = strings.Split(specContainer.Image, ":")[0] + "@" + digest
				log.Printf("  %s has to be updated to %s", container, result[container])
			} else {
				log.Printf("  %s ok", container)
			}
		}
	}
	return result
}

func (c *Config) getRunningImagesFor(obj *parentController) map[string]string {
	var pods []v1.Pod
	for _, pod := range c.getPods().Items {
		if pod.ObjectMeta.Namespace != obj.ObjectMeta.Namespace {
			continue
		}
		for _, owner := range pod.OwnerReferences {
			if owner.Kind == "ReplicaSet" && obj.Kind == "Deployment" {
				for _, rs := range c.getReplicaSets().Items {
					if rs.ObjectMeta.Namespace != obj.ObjectMeta.Namespace || rs.ObjectMeta.Name != owner.Name {
						continue
					}
					for _, rsOwner := range rs.OwnerReferences {
						if rsOwner.Kind == obj.Kind && rsOwner.Name == obj.ObjectMeta.Name {
							pods = append(pods, pod)
						}
					}
				}
			} else if owner.Kind == obj.Kind && owner.Name == obj.ObjectMeta.Name {
				pods = append(pods, pod)
			}
		}
	}
	result := make(map[string]string)
	for _, pod := range pods {
		for _, container := range pod.Status.ContainerStatuses {
			if result[container.Name] != "" {
				log.Fatal("Two different running images")
			}
			result[container.Name] = container.ImageID
		}
	}
	return result
}

func mapKeys(m map[string]string) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	return result
}

func (c *Config) setImage(namespace, kind, name string, images map[string]string) {
	if len(images) == 0 || c.dryrun {
		return
	}
	log.Printf("Update %s/%s/%s set images %s", namespace, kind, name, strings.Join(mapKeys(images), ","))
	var setPodTemplateSpecImage = func(spec *v1.PodTemplateSpec) {
		for i, container := range spec.Spec.Containers {
			if newImage, ok := images[container.Name]; ok {
				spec.Spec.Containers[i].Image = newImage
			}
		}
	}
	var updateResource func() error
	switch kind {
	case "Deployment":
		updateResource = func() error {
			client := c.cluster.AppsV1().Deployments(namespace)
			resource, err := client.Get(name, metav1.GetOptions{})
			if err != nil {
				log.Fatal(err)
			}
			setPodTemplateSpecImage(&resource.Spec.Template)
			_, err = client.Update(resource)
			return err
		}
	case "DaemonSet":
		updateResource = func() error {
			client := c.cluster.AppsV1().DaemonSets(namespace)
			resource, err := client.Get(name, metav1.GetOptions{})
			if err != nil {
				log.Fatal(err)
			}
			setPodTemplateSpecImage(&resource.Spec.Template)
			_, err = client.Update(resource)
			return err
		}
	default:
		log.Fatalf("Unhandled kind %s", kind)
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, updateResource); err != nil {
		log.Fatal(err)
	}
}

func inClusterClientPossible() bool {
	fi, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
		os.Getenv("KUBERNETES_SERVICE_PORT") != "" &&
		err == nil && !fi.IsDir()
}

func inClusterNamespace() string {
	data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Fatal(err)
	}
	if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
		return ns
	}
	return ""
}

func outClusterNamespace(kubeconfig string) string {
	config := clientcmd.GetConfigFromFileOrDie(kubeconfig)
	if len(config.Contexts) == 0 || config.Contexts[config.CurrentContext] == nil {
		log.Fatal("No kubernetes contexts availables")
	}
	return config.Contexts[config.CurrentContext].Namespace
}

func homeDir() string {
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return user.HomeDir
}

func main() {
	var kubeconfig string
	var labelSelector string
	var fieldSelector string
	var allnamespaces bool
	var namespace string
	var dryrun bool
	flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(homeDir(), ".kube", "config"), "kube config file")
	flag.StringVar(&namespace, "n", "", "Check deployments and daemonsets in given namespace (default to current namespace)")
	flag.StringVar(&labelSelector, "l", "", "Kubernetes labels selectors\nWarning: applies to Deployment and DaemonSet, not pods !")
	flag.StringVar(&fieldSelector, "field-selector", "", "Kubernetes field-selector\nexample: metadata.name=myapp")
	flag.BoolVar(&allnamespaces, "all-namespaces", false, "Check deployments and daemonsets on all namespaces (default false)")
	flag.BoolVar(&dryrun, "dry-run", false, "dry run mode. Do not update any deployments and daemonsets (default false)")
	flag.Parse()
	c := NewConfig(kubeconfig, namespace, allnamespaces, dryrun)
	c.Update(fieldSelector, labelSelector)
}
