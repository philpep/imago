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
	batchv1 "k8s.io/api/batch/v1"
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

func getDigestURL(image string) string {
	u, err := url.Parse(fmt.Sprintf("https://%s", image))
	if err != nil {
		log.Fatal(err)
	}
	host := u.Host
	path := u.Path
	tag := "latest"
	if host == image || (!strings.Contains(host, ".") && !strings.Contains(host, ":")) {
		host = "registry.hub.docker.com"
		if !strings.Contains(path, "/") {
			path = "/library/" + image
		} else {
			path = "/" + image
		}
	}
	if strings.Contains(path, ":") {
		s := strings.Split(path, ":")
		path, tag = s[0], s[1]
	}
	return fmt.Sprintf("%s://%s/v2%s/manifests/%s", u.Scheme, host, path, tag)
}

func getBearerToken(authHeader string) string {
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
	client := &http.Client{
		Timeout: time.Second * 10,
	}
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

func homeDir() string {
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return user.HomeDir
}

func getDigest(image string, credentials map[string]string) string {
	digestURL := getDigestURL(image)
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("HEAD", digestURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	u, err := url.Parse(digestURL)
	if err != nil {
		log.Fatal(err)
	}
	basicauth := credentials[u.Host]
	if basicauth != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basicauth))
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer closeResource(resp.Body)
	authenticate := resp.Header.Get("www-authenticate")
	if resp.StatusCode == 401 && strings.HasPrefix(authenticate, "Bearer ") {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", getBearerToken(authenticate)))
		resp, err = client.Do(req)
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

func decodeRegistryCredential(secret *v1.Secret) map[string]string {
	result := make(map[string]string)
	var dockerconfig struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	err := json.Unmarshal(secret.Data[v1.DockerConfigJsonKey], &dockerconfig)
	if err != nil {
		log.Fatal(err)
	}
	for registry, auth := range dockerconfig.Auths {
		result[registry] = auth.Auth
	}
	return result
}

type kubernetesImageSync struct {
	client      *kubernetes.Clientset
	pods        *v1.PodList
	replicasets *appsv1.ReplicaSetList
	jobs        *batchv1.JobList
	imageCache  map[string]string
	secretCache map[string]*v1.Secret
	namespace   string
	dryrun      bool
}

func (c *kubernetesImageSync) getPods() *v1.PodList {
	if c.pods == nil {
		var err error
		c.pods, err = c.client.CoreV1().Pods(c.namespace).List(metav1.ListOptions{FieldSelector: "status.phase=Running"})
		if err != nil {
			log.Fatal(err)
		}
	}
	return c.pods
}

func (c *kubernetesImageSync) getReplicaSets() *appsv1.ReplicaSetList {
	if c.replicasets == nil {
		var err error
		c.replicasets, err = c.client.AppsV1().ReplicaSets(c.namespace).List(metav1.ListOptions{})
		if err != nil {
			log.Fatal(err)
		}
	}
	return c.replicasets
}

func (c *kubernetesImageSync) getJobs() *batchv1.JobList {
	if c.jobs == nil {
		var err error
		c.jobs, err = c.client.BatchV1().Jobs(c.namespace).List(metav1.ListOptions{})
		if err != nil {
			log.Fatal(err)
		}
	}
	return c.jobs
}

func (c *kubernetesImageSync) getRegistrySecret(namespace string, name string) *v1.Secret {
	key := fmt.Sprintf("%s/%s", namespace, name)
	if c.secretCache == nil {
		c.secretCache = make(map[string]*v1.Secret)
	}
	if c.secretCache[key] == nil {
		secret, err := c.client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			log.Fatal(err)
		}
		c.secretCache[key] = secret
	}
	return c.secretCache[key]
}

func (c *kubernetesImageSync) getNewImages(kind string, meta *metav1.ObjectMeta, spec *v1.PodSpec) map[string]string {
	log.Printf("checking %s/%s:", kind, meta.Name)
	result := make(map[string]string)
	registryCredentials := make(map[string]string)
	for _, secret := range spec.ImagePullSecrets {
		for registry, auth := range decodeRegistryCredential(c.getRegistrySecret(meta.Namespace, secret.Name)) {
			registryCredentials[registry] = auth
		}
	}
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
			digest := c.getDigest(specContainer.Image, registryCredentials)
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

func (c *kubernetesImageSync) getDigest(image string, credentials map[string]string) string {
	if c.imageCache == nil {
		c.imageCache = make(map[string]string)
	}
	if c.imageCache[image] == "" {
		c.imageCache[image] = getDigest(image, credentials)
	}
	return c.imageCache[image]
}

func (c *kubernetesImageSync) getRunningImagesFor(obj *parentController) map[string]string {
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

func (c *kubernetesImageSync) deploymentSetImage(namespace string, name string, images map[string]string) {
	if len(images) == 0 || c.dryrun {
		return
	}
	log.Printf("update Deployment/%s images %s", name, strings.Join(mapKeys(images), ","))
	client := c.client.AppsV1().Deployments(namespace)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		result, err := client.Get(name, metav1.GetOptions{})
		if err != nil {
			log.Fatal(err)
		}
		for i, container := range result.Spec.Template.Spec.Containers {
			if newImage, ok := images[container.Name]; ok {
				result.Spec.Template.Spec.Containers[i].Image = newImage
			}
		}
		_, updateErr := client.Update(result)
		return updateErr
	}); err != nil {
		log.Fatal(err)
	}
}

func (c *kubernetesImageSync) daemonSetSetImage(namespace string, name string, images map[string]string) {
	if len(images) == 0 || c.dryrun {
		return
	}
	client := c.client.AppsV1().DaemonSets(namespace)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		result, err := client.Get(name, metav1.GetOptions{})
		if err != nil {
			log.Fatal(err)
		}
		for i, container := range result.Spec.Template.Spec.Containers {
			if newImage, ok := images[container.Name]; ok {
				result.Spec.Template.Spec.Containers[i].Image = newImage
			}
		}
		_, updateErr := client.Update(result)
		return updateErr
	}); err != nil {
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

func (c *kubernetesImageSync) initClient(kubeconfig string) {
	var err error
	var config *rest.Config
	if inClusterClientPossible() {
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
		if c.namespace = inClusterNamespace(); c.namespace == "" {
			log.Fatal("Could not determine current namespace")
		}
	} else {
		kconfig := clientcmd.GetConfigFromFileOrDie(kubeconfig)
		if len(kconfig.Contexts) == 0 || kconfig.Contexts[kconfig.CurrentContext] == nil {
			log.Fatal("No kubernetes contexts availables")
		}
		if c.namespace == "" {
			c.namespace = kconfig.Contexts[kconfig.CurrentContext].Namespace
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatal(err)
		}
	}
	c.client, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	var err error
	var kubeconfig string
	var labelSelector string
	var fieldSelector string
	var allnamespaces bool
	c := kubernetesImageSync{}
	flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(homeDir(), ".kube", "config"), "kube config file")
	flag.StringVar(&c.namespace, "n", "", "Check deployments and daemonsets in given namespace (default to current namespace)")
	flag.StringVar(&labelSelector, "l", "", "Kubernetes labels selectors\nWarning: applies to Deployment and DaemonSet, not pods !")
	flag.StringVar(&fieldSelector, "field-selector", "", "Kubernetes field-selector\nexample: metadata.name=myapp")
	flag.BoolVar(&allnamespaces, "all-namespaces", false, "Check deployments and daemonsets on all namespaces (default false)")
	flag.BoolVar(&c.dryrun, "dry-run", false, "dry run mode. Do not update any deployments and daemonsets (default false)")
	flag.Parse()
	c.initClient(kubeconfig)
	if allnamespaces {
		c.namespace = ""
	}
	appsv1Client := c.client.AppsV1()
	c.replicasets, err = appsv1Client.ReplicaSets(c.namespace).List(metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}
	opts := metav1.ListOptions{FieldSelector: fieldSelector, LabelSelector: labelSelector}
	deployments, err := appsv1Client.Deployments(c.namespace).List(opts)
	if err != nil {
		log.Fatal(err)
	}
	for _, deployment := range deployments.Items {
		images := c.getNewImages("Deployment", &deployment.ObjectMeta, &deployment.Spec.Template.Spec)
		c.deploymentSetImage(deployment.ObjectMeta.Namespace, deployment.ObjectMeta.Name, images)
	}
	daemonsets, err := appsv1Client.DaemonSets(c.namespace).List(opts)
	if err != nil {
		log.Fatal(err)
	}
	for _, daemonset := range daemonsets.Items {
		images := c.getNewImages("DaemonSet", &daemonset.ObjectMeta, &daemonset.Spec.Template.Spec)
		c.daemonSetSetImage(daemonset.ObjectMeta.Namespace, daemonset.ObjectMeta.Name, images)
	}
}
