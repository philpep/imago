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

// Config represent a imago configuration
type Config struct {
	cluster     *kubernetes.Clientset
	reg         *RegistryClient
	secretCache map[string]*v1.Secret
	namespace   string
	update      bool
	checkpods   bool
}

// NewConfig initialize a new imago config
func NewConfig(kubeconfig string, namespace string, allnamespaces bool, update bool, checkpods bool) *Config {
	c := &Config{reg: NewRegistryClient(nil), update: update, checkpods: checkpods}
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
		c.setImages("Deployment", &d.ObjectMeta, &d.Spec.Template)
	}
	daemonsets, err := client.DaemonSets(c.namespace).List(opts)
	if err != nil {
		log.Fatal(err)
	}
	for _, ds := range daemonsets.Items {
		c.setImages("DaemonSet", &ds.ObjectMeta, &ds.Spec.Template)
	}
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

type configAnnotationImageSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type configAnnotation struct {
	Containers     []configAnnotationImageSpec `json:"containers"`
	InitContainers []configAnnotationImageSpec `json:"initContainers"`
}

const imagoConfigAnnotation = "imago-config-spec"

func mergeContainers(configContainers []configAnnotationImageSpec, containers []v1.Container) []configAnnotationImageSpec {
	specImages := make(map[string]string)
	for _, c := range containers {
		specImages[c.Name] = c.Image
	}
	re := regexp.MustCompile(".*@(sha256:.*)")
	configImages := make(map[string]string)
	for _, c := range configContainers {
		// drop containers in spec but not in config
		image := specImages[c.Name]
		if image != "" {
			match := re.FindStringSubmatch(image)
			if len(match) > 1 {
				// keep stored config
				configImages[c.Name] = c.Image
			} else {
				// use newer image
				configImages[c.Name] = specImages[c.Name]
			}
		}
	}
	for name, image := range specImages {
		if configImages[name] == "" {
			configImages[name] = image
		}
	}
	result := make([]configAnnotationImageSpec, 0)
	for name, image := range configImages {
		result = append(result, configAnnotationImageSpec{
			Name: name, Image: image})
	}
	return result
}

func getConfigAnontation(meta *metav1.ObjectMeta, spec *v1.PodSpec) *configAnnotation {
	config := configAnnotation{}
	rawConfig := meta.GetAnnotations()[imagoConfigAnnotation]
	if len(rawConfig) > 0 {
		err := json.Unmarshal([]byte(rawConfig), &config)
		if err != nil {
			log.Fatal(err)
		}
	}
	config.Containers = mergeContainers(config.Containers, spec.Containers)
	config.InitContainers = mergeContainers(config.InitContainers, spec.InitContainers)
	return &config
}

func needUpdate(name string, image string, specImage string, running map[string]string) bool {
	if len(running) == 0 {
		if image != specImage {
			log.Printf("    %s need to be updated from %s to %s", name, specImage, image)
			return true
		}
		log.Printf("    %s ok", name)
		return false
	}
	result := false
	for pod, digest := range running {
		if digest != image {
			log.Printf("    %s on %s need to be updated from %s to %s", name, pod, digest, image)
			result = true
		} else {
			log.Printf("    %s on %s ok", name, pod)
		}
	}
	return result
}

func (c *Config) getUpdates(configContainers []configAnnotationImageSpec, containers []v1.Container, running map[string]map[string]string) map[string]string {
	re := regexp.MustCompile(".*@(sha256:.*)")
	update := make(map[string]string)
	for _, container := range configContainers {
		match := re.FindStringSubmatch(container.Image)
		if len(match) > 1 {
			log.Printf("    %s ok (fixed digest)", container.Name)
			continue
		}
		digest := c.reg.GetDigest(container.Image)
		image := strings.Split(container.Image, ":")[0] + "@" + digest
		for _, specContainer := range containers {
			if specContainer.Name != container.Name {
				continue
			}
			if needUpdate(container.Name, image, specContainer.Image, running[container.Name]) {
				update[container.Name] = image
			}
		}
	}
	return update
}

func getSelector(labels map[string]string) string {
	filters := make([]string, 0)
	for key, value := range labels {
		filters = append(filters, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(filters, ", ")
}

func (c *Config) getRunningContainers(kind string, meta *metav1.ObjectMeta, template *v1.PodTemplateSpec) (map[string]map[string]string, map[string]map[string]string) {
	runningInitContainers, runningContainers := make(map[string]map[string]string), make(map[string]map[string]string)
	if !c.checkpods {
		return runningInitContainers, runningContainers
	}
	labelSelector := getSelector(template.ObjectMeta.Labels)
	running, err := c.cluster.CoreV1().Pods(meta.Namespace).List(metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		log.Fatal(err)
	}
	match := func(pod *v1.Pod) bool {
		for _, owner := range pod.OwnerReferences {
			switch owner.Kind {
			case "ReplicaSet":
				rs, err := c.cluster.AppsV1().ReplicaSets(meta.Namespace).Get(owner.Name, metav1.GetOptions{})
				if err != nil {
					log.Fatal(err)
				}
				for _, rsOwner := range rs.OwnerReferences {
					if rsOwner.Kind == kind && rsOwner.Name == meta.Name {
						return true
					}
				}
			case "DaemonSet":
				if owner.Kind == kind && owner.Name == meta.Name {
					return true
				}
			default:
				log.Fatalf("unhandled %s", owner.Kind)
			}
		}
		return false
	}
	re := regexp.MustCompile(".*://(.*@sha256:.*)")
	addImage := func(containers map[string]map[string]string, name string, podName string, image string) {
		reMatch := re.FindStringSubmatch(image)
		if len(reMatch) < 2 {
			log.Printf("Unable to parse image digest %s", image)
			return
		}
		if containers[name] == nil {
			containers[name] = make(map[string]string)
		}
		containers[name][podName] = reMatch[1]
	}
	for _, pod := range running.Items {
		if match(&pod) {
			runningInitContainers[pod.Name] = make(map[string]string)
			runningContainers[pod.Name] = make(map[string]string)
			for _, container := range pod.Status.InitContainerStatuses {
				addImage(runningInitContainers, container.Name, pod.Name, container.ImageID)
			}
			for _, container := range pod.Status.ContainerStatuses {
				addImage(runningContainers, container.Name, pod.Name, container.ImageID)
			}
		}
	}
	return runningInitContainers, runningContainers
}

func (c *Config) setImages(kind string, meta *metav1.ObjectMeta, template *v1.PodTemplateSpec) {
	log.Printf("checking %s/%s/%s", meta.Namespace, kind, meta.Name)
	c.setRegistryCredentials(meta.Namespace, template.Spec.ImagePullSecrets)
	config := getConfigAnontation(meta, &template.Spec)
	runningInitContainers, runningContainers := c.getRunningContainers(kind, meta, template)
	updateInitContainers := c.getUpdates(config.InitContainers, template.Spec.InitContainers, runningInitContainers)
	updateContainers := c.getUpdates(config.Containers, template.Spec.Containers, runningContainers)
	if !c.update || (len(updateContainers) == 0 && len(updateInitContainers) == 0) {
		return
	}
	log.Printf("update %s/%s/%s", meta.Namespace, kind, meta.Name)
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	jsonConfigString := string(jsonConfig)
	var setAnnotation = func(meta *metav1.ObjectMeta) {
		if meta.Annotations == nil {
			meta.Annotations = make(map[string]string)
		}
		meta.Annotations[imagoConfigAnnotation] = jsonConfigString
	}
	var updateSpec = func(containers []v1.Container, update map[string]string) {
		for i, container := range containers {
			if newImage, ok := update[container.Name]; ok {
				containers[i].Image = newImage
			}
		}
	}
	var updateResource func() error
	switch kind {
	case "Deployment":
		updateResource = func() error {
			client := c.cluster.AppsV1().Deployments(meta.Namespace)
			resource, err := client.Get(meta.Name, metav1.GetOptions{})
			if err != nil {
				log.Fatal(err)
			}
			setAnnotation(&resource.ObjectMeta)
			updateSpec(resource.Spec.Template.Spec.Containers, updateContainers)
			updateSpec(resource.Spec.Template.Spec.InitContainers, updateInitContainers)
			_, err = client.Update(resource)
			return err
		}
	case "DaemonSet":
		updateResource = func() error {
			client := c.cluster.AppsV1().DaemonSets(meta.Namespace)
			resource, err := client.Get(meta.Name, metav1.GetOptions{})
			if err != nil {
				log.Fatal(err)
			}
			setAnnotation(&resource.ObjectMeta)
			updateSpec(resource.Spec.Template.Spec.Containers, updateContainers)
			updateSpec(resource.Spec.Template.Spec.InitContainers, updateInitContainers)
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
	var update bool
	var checkpods bool
	flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(homeDir(), ".kube", "config"), "kube config file")
	flag.StringVar(&namespace, "n", "", "Check deployments and daemonsets in given namespace (default to current namespace)")
	flag.StringVar(&labelSelector, "l", "", "Kubernetes labels selectors\nWarning: applies to Deployment and DaemonSet, not pods !")
	flag.StringVar(&fieldSelector, "field-selector", "", "Kubernetes field-selector\nexample: metadata.name=myapp")
	flag.BoolVar(&allnamespaces, "all-namespaces", false, "Check deployments and daemonsets on all namespaces (default false)")
	flag.BoolVar(&update, "update", false, "update deployments and daemonsets to use newer images (default false)")
	flag.BoolVar(&checkpods, "check-pods", false, "check image digests of running pods (default false)")
	flag.Parse()
	c := NewConfig(kubeconfig, namespace, allnamespaces, update, checkpods)
	c.Update(fieldSelector, labelSelector)
}
