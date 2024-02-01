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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
)

var digestCache = map[string]string{}

// GetDigest return the docker digest of given image name
func GetDigest(ctx context.Context, name string) (string, error) {
	if digestCache[name] != "" {
		return digestCache[name], nil
	}
	ref, err := docker.ParseReference("//" + name)
	if err != nil {
		return "", err
	}
	img, err := ref.NewImage(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := img.Close(); err != nil {
			log.Print(err)
		}
	}()
	b, _, err := img.Manifest(ctx)
	if err != nil {
		return "", err
	}
	digest, err := manifest.Digest(b)
	if err != nil {
		return "", err
	}
	digeststr := string(digest)
	digestCache[name] = digeststr
	return digeststr, nil
}

// Config represent a imago configuration
type Config struct {
	cluster    *kubernetes.Clientset
	namespace  string
	policy     string
	checkpods  bool
	xnamespace *arrayFlags
	context    context.Context
}

// NewConfig initialize a new imago config
func NewConfig(kubeconfig string, namespace string, allnamespaces bool, xnamespace *arrayFlags, policy string, checkpods bool, ctx context.Context) (*Config, error) {
	c := &Config{policy: policy, checkpods: checkpods, xnamespace: xnamespace, context: ctx}
	var err error
	var clusterConfig *rest.Config

	setNamespace := func(incluster bool) error {
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
				c.namespace = "default"
			}
		}
		return nil
	}

	if inClusterClientPossible() {
		clusterConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		if err = setNamespace(true); err != nil {
			return nil, err
		}
	} else {
		clusterConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		if err = setNamespace(false); err != nil {
			return nil, err
		}
	}
	c.cluster, err = kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Update Deployment, DaemonSet and CronJob matching given selectors
func (c *Config) Update(fieldSelector, labelSelector string) error {
	ctx := c.context
	client := c.cluster.AppsV1()
	opts := metav1.ListOptions{FieldSelector: fieldSelector, LabelSelector: labelSelector}
	deployments, err := client.Deployments(c.namespace).List(ctx, opts)
	if err != nil {
		return err
	}
	failed := make([]string, 0)
	for _, d := range deployments.Items {
		if err = c.process("Deployment", &d.ObjectMeta, &d.Spec.Template); err != nil {
			log.Print(err)
			failed = append(failed, fmt.Sprintf("failed to check %s/Deployment/%s: %s", d.ObjectMeta.Namespace, d.Name, err))
		}
	}
	daemonsets, err := client.DaemonSets(c.namespace).List(ctx, opts)
	if err != nil {
		return err
	}
	for _, ds := range daemonsets.Items {
		if err := c.process("DaemonSet", &ds.ObjectMeta, &ds.Spec.Template); err != nil {
			failed = append(failed, fmt.Sprintf("failed to check %s/DaemonSet/%s: %s", ds.ObjectMeta.Namespace, ds.Name, err))
		}
	}
	statefulsets, err := client.StatefulSets(c.namespace).List(ctx, opts)
	if err != nil {
		return err
	}
	for _, sts := range statefulsets.Items {
		if err := c.process("StatefulSet", &sts.ObjectMeta, &sts.Spec.Template); err != nil {
			failed = append(failed, fmt.Sprintf("failed to check %s/StatefulSet/%s: %s", sts.ObjectMeta.Namespace, sts.Name, err))
		}
	}
	cronjobs, err := c.cluster.BatchV1().CronJobs(c.namespace).List(ctx, opts)
	if err != nil {
		return err
	}
	for _, cron := range cronjobs.Items {
		if err := c.process("CronJob", &cron.ObjectMeta, &cron.Spec.JobTemplate.Spec.Template); err != nil {
			failed = append(failed, fmt.Sprintf("failed to check %s/CronJob/%s: %s", cron.ObjectMeta.Namespace, cron.Name, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf(strings.Join(failed, "\n"))
	}
	return nil
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
const imagoRestartedAtAnnotation = "imago/restartedAt"

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

func getConfigAnnotation(meta *metav1.ObjectMeta, spec *v1.PodSpec) (*configAnnotation, error) {
	config := configAnnotation{}
	rawConfig := meta.GetAnnotations()[imagoConfigAnnotation]
	if len(rawConfig) > 0 {
		err := json.Unmarshal([]byte(rawConfig), &config)
		if err != nil {
			return nil, err
		}
	}
	config.Containers = mergeContainers(config.Containers, spec.Containers)
	config.InitContainers = mergeContainers(config.InitContainers, spec.InitContainers)
	return &config, nil
}

func needUpdate(name string, image string, specImage string) bool {
	if image != specImage {
		log.Printf("    %s need to be updated from %s to %s", name, specImage, image)
		return true
	}
	log.Printf("    %s ok", name)
	return false
}

func needRestart(name string, image string, running map[string]string) bool {
	result := false

	// If `image` contains a SHA-256 digest, then it doesn't need to match exactly the name of the
	// running image, as long as the digests match up. To check this, we first extract the digest
	// from `image`.
	digest := ""
	re := regexp.MustCompile(".*@(sha256:.*)")
	match := re.FindStringSubmatch(image)
	if len(match) > 1 {
		digest = match[1]
	}

	for pod, runningImage := range running {
		if runningImage == image {
			log.Printf("    %s on %s ok", name, pod)
			continue
		}
		// The image names don't exactly match, but maybe they have matching SHA-256 digests:
		if digest != "" {
			match = re.FindStringSubmatch(runningImage)
			if len(match) > 1 && match[1] == digest {
				log.Printf("    %s on %s ok", name, pod)
				continue
			}
		}
		log.Printf("    %s on %s need to be updated from %s to %s", name, pod, runningImage, image)
		result = true
	}
	return result
}

func (c *Config) getUpdates(configContainers []configAnnotationImageSpec, containers []v1.Container, running map[string]map[string]string) map[string]string {
	ctx := c.context
	reDigest := regexp.MustCompile(".*@(sha256:.*)")
	// We construct a regex to obtain the image name without tag by removing the tag if present.
	// A tag can contain lower case letters, upper case letters, digits, underscore, dot, and dash.
	reImageName := regexp.MustCompile(`(.*)(:[a-zA-Z0-9_\.-]*)?`)
	update := make(map[string]string)
	for _, container := range configContainers {
		match := reDigest.FindStringSubmatch(container.Image)
		if len(match) > 1 {
			log.Printf("    %s ok (fixed digest)", container.Name)
			continue
		}
		digest, err := GetDigest(ctx, container.Image)
		if err != nil {
			log.Printf("    %s unable to get digest: %s", container.Name, err)
			continue
		}
		match = reImageName.FindStringSubmatch(container.Image)
		image := match[1] + "@" + digest
		if !c.checkpods {
			for _, specContainer := range containers {
				if specContainer.Name != container.Name {
					continue
				}
				if needUpdate(container.Name, image, specContainer.Image) {
					update[container.Name] = image
				}
			}
		} else if needRestart(container.Name, image, running[container.Name]) {
			update[container.Name] = image
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

func (c *Config) getRunningContainers(kind string, meta *metav1.ObjectMeta, template *v1.PodTemplateSpec) (map[string]map[string]string, map[string]map[string]string, error) {
	ctx := c.context
	runningInitContainers, runningContainers := make(map[string]map[string]string), make(map[string]map[string]string)
	if !c.checkpods {
		return runningInitContainers, runningContainers, nil
	}
	labelSelector := getSelector(template.ObjectMeta.Labels)
	running, err := c.cluster.CoreV1().Pods(meta.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "status.phase=Running", LabelSelector: labelSelector})
	if err != nil {
		return runningInitContainers, runningContainers, err
	}
	match := func(pod *v1.Pod) bool {
		for _, owner := range pod.OwnerReferences {
			switch owner.Kind {
			case "ReplicaSet":
				rs, err := c.cluster.AppsV1().ReplicaSets(meta.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err != nil {
					log.Print(err)
					continue
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
			case "StatefulSet":
				if owner.Kind == kind && owner.Name == meta.Name {
					return true
				}
			}
		}
		return false
	}
	re := regexp.MustCompile("(.*://)?(.*@sha256:.*)")
	addImage := func(containers map[string]map[string]string, name string, podName string, image string, imageId string) {
		reMatch := re.FindStringSubmatch(imageId)
		newImageId := ""
		if len(reMatch) < 3 {
			if regexp.MustCompile("[a-z0-9]+").MatchString(image) {
				ref, err := docker.ParseReference("//" + image)
				if err != nil {
					log.Print(err)
					return
				}
				newImageId = reference.TrimNamed(ref.DockerReference()).Name()
			} else {
				log.Printf("Unable to parse image digest (image %s, imageId %s)", image, imageId)
				return
			}
		} else {
			newImageId = reMatch[2]
		}
		if containers[name] == nil {
			containers[name] = make(map[string]string)
		}
		containers[name][podName] = newImageId
	}
	for _, pod := range running.Items {
		if match(&pod) {
			runningInitContainers[pod.Name] = make(map[string]string)
			runningContainers[pod.Name] = make(map[string]string)
			for _, container := range pod.Status.InitContainerStatuses {
				addImage(runningInitContainers, container.Name, pod.Name, container.Image, container.ImageID)
			}
			for _, container := range pod.Status.ContainerStatuses {
				addImage(runningContainers, container.Name, pod.Name, container.Image, container.ImageID)
			}
		}
	}
	return runningInitContainers, runningContainers, nil
}

func (c *Config) process(kind string, meta *metav1.ObjectMeta, template *v1.PodTemplateSpec) error {
	ctx := c.context
	if c.xnamespace.Contains(meta.Namespace) {
		// namespace excluded from selection
		return nil
	}
	log.Printf("checking %s/%s/%s", meta.Namespace, kind, meta.Name)
	config, err := getConfigAnnotation(meta, &template.Spec)
	if err != nil {
		return err
	}
	runningInitContainers, runningContainers, err := c.getRunningContainers(kind, meta, template)
	if err != nil {
		return err
	}
	updateInitContainers := c.getUpdates(config.InitContainers, template.Spec.InitContainers, runningInitContainers)
	updateContainers := c.getUpdates(config.Containers, template.Spec.Containers, runningContainers)
	if c.policy == "" || (len(updateContainers) == 0 && len(updateInitContainers) == 0) {
		return nil
	}
	log.Printf("%s %s/%s/%s", c.policy, meta.Namespace, kind, meta.Name)
	var policyUpdateResource func(*metav1.ObjectMeta, *v1.PodTemplateSpec) error
	switch c.policy {
	case "update":
		policyUpdateResource = func(meta *metav1.ObjectMeta, template *v1.PodTemplateSpec) error {
			jsonConfig, err := json.Marshal(config)
			if err != nil {
				return err
			}
			jsonConfigString := string(jsonConfig)
			if meta.Annotations == nil {
				meta.Annotations = make(map[string]string)
			}
			meta.Annotations[imagoConfigAnnotation] = jsonConfigString
			var updateSpec = func(containers []v1.Container, update map[string]string) {
				for i, container := range containers {
					if newImage, ok := update[container.Name]; ok {
						containers[i].Image = newImage
					}
				}
			}
			updateSpec(template.Spec.Containers, updateContainers)
			updateSpec(template.Spec.InitContainers, updateInitContainers)
			return nil
		}
	case "restart":
		policyUpdateResource = func(meta *metav1.ObjectMeta, template *v1.PodTemplateSpec) error {
			if meta.Annotations[imagoConfigAnnotation] != "" {
				log.Printf("deleting %s annotation and reset images", imagoConfigAnnotation)
				delete(meta.Annotations, imagoConfigAnnotation)
				var updateSpec = func(containers []v1.Container, updates []configAnnotationImageSpec) {
					for i, container := range containers {
						for _, origContainer := range updates {
							if origContainer.Name == container.Name {
								containers[i].Image = origContainer.Image
							}
						}
					}
				}
				updateSpec(template.Spec.Containers, config.Containers)
				updateSpec(template.Spec.InitContainers, config.InitContainers)
			}
			if kind == "CronJob" {
				return nil
			}
			if template.ObjectMeta.Annotations == nil {
				template.ObjectMeta.Annotations = make(map[string]string)
			}
			template.ObjectMeta.Annotations[imagoRestartedAtAnnotation] = time.Now().Format(time.RFC3339)
			return nil
		}
	}
	var updateResource func() error
	switch kind {
	case "Deployment":
		updateResource = func() error {
			client := c.cluster.AppsV1().Deployments(meta.Namespace)
			resource, err := client.Get(ctx, meta.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if err = policyUpdateResource(&resource.ObjectMeta, &resource.Spec.Template); err != nil {
				return err
			}
			_, err = client.Update(ctx, resource, metav1.UpdateOptions{})
			return err
		}
	case "DaemonSet":
		updateResource = func() error {
			client := c.cluster.AppsV1().DaemonSets(meta.Namespace)
			resource, err := client.Get(ctx, meta.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if err = policyUpdateResource(&resource.ObjectMeta, &resource.Spec.Template); err != nil {
				return err
			}
			_, err = client.Update(ctx, resource, metav1.UpdateOptions{})
			return err
		}
	case "StatefulSet":
		updateResource = func() error {
			client := c.cluster.AppsV1().StatefulSets(meta.Namespace)
			resource, err := client.Get(ctx, meta.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if err = policyUpdateResource(&resource.ObjectMeta, &resource.Spec.Template); err != nil {
				return err
			}
			_, err = client.Update(ctx, resource, metav1.UpdateOptions{})
			return err
		}
	case "CronJob":
		updateResource = func() error {
			client := c.cluster.BatchV1().CronJobs(meta.Namespace)
			resource, err := client.Get(ctx, meta.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if err = policyUpdateResource(&resource.ObjectMeta, &resource.Spec.JobTemplate.Spec.Template); err != nil {
				return err
			}
			_, err = client.Update(ctx, resource, metav1.UpdateOptions{})
			return err
		}
	default:
		return fmt.Errorf("unhandled kind %s", kind)
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, updateResource); err != nil {
		return err
	}
	return nil
}

func inClusterClientPossible() bool {
	fi, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
		os.Getenv("KUBERNETES_SERVICE_PORT") != "" &&
		err == nil && !fi.IsDir()
}

func defaultKubeConfig() string {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(homeDir(), ".kube", "config")
	}
	return kubeconfig
}

func inClusterNamespace() string {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
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

type arrayFlags []string

func (i *arrayFlags) String() string {
	return ""
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func (i *arrayFlags) Contains(value string) bool {
	for _, x := range *i {
		if x == value {
			return true
		}
	}
	return false
}

func main() {
	var kubeconfig string
	var labelSelector string
	var fieldSelector string
	var allnamespaces bool
	var namespace arrayFlags
	var xnamespace arrayFlags
	var update bool
	var restart bool
	var checkpods bool
	flag.StringVar(&kubeconfig, "kubeconfig", defaultKubeConfig(), "kube config file")
	flag.Var(&namespace, "n", "Check deployments and daemonsets in given namespaces (default to current namespace)")
	flag.Var(&xnamespace, "x", "Check deployments and daemonsets in all namespaces except given namespaces (implies --all-namespaces)")
	flag.StringVar(&labelSelector, "l", "", "Kubernetes labels selectors\nWarning: applies to Deployment, DaemonSet, StatefulSet and CronJob, not pods !")
	flag.StringVar(&fieldSelector, "field-selector", "", "Kubernetes field-selector\nexample: metadata.name=myapp")
	flag.BoolVar(&allnamespaces, "all-namespaces", false, "Check deployments and daemonsets on all namespaces (default false)")
	flag.BoolVar(&allnamespaces, "A", false, "Check deployments and daemonsets on all namespaces (shorthand) (default false)")
	flag.BoolVar(&update, "update", false, "update deployments and daemonsets to use newer images (default false)")
	flag.BoolVar(&restart, "restart", false, "rollout restart deployments and daemonsets to use newer images, implies -check-pods and assume imagePullPolicy is Always (default false)")
	flag.BoolVar(&checkpods, "check-pods", false, "check image digests of running pods (default false)")
	flag.Parse()
	if allnamespaces && len(namespace) > 0 {
		log.Fatal("You can't use -n with --all-namespaces")
	}
	if len(namespace) == 0 {
		namespace = append(namespace, "")
	}
	if len(xnamespace) > 0 {
		allnamespaces = true
	}
	var policy string
	if restart {
		policy = "restart"
		checkpods = true
	} else if update {
		policy = "update"
	}
	for _, ns := range namespace {
		ctx := context.Background()
		c, err := NewConfig(kubeconfig, ns, allnamespaces, &xnamespace, policy, checkpods, ctx)
		if err != nil {
			log.Fatal(err)
		}
		if err := c.Update(fieldSelector, labelSelector); err != nil {
			log.Fatal(err)
		}
	}
}
