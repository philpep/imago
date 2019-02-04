=====================
Kubernetes image sync
=====================

This project aims to ease continuous delivery of docker images in a kubernetes
cluster.

`kubernetes-image-sync` looks for kubernetes `Deployments` and `DaemonSets`
configuration and check if running `Pods` use the correct image sha256 digest
from the docker repository and update `Deployments` or `DaemonSets` to use the
correct image.

Users and/or CI might trigger rebuild of images (for instance in case of
security update). For a given docker image tag the actual content may be
updated, `kubernetes-image-sync` ensure you cluster is running the latest build.

How it works ?
==============

`kubernetes-image-sync` looks for `Deployments` and `DaemonSets` configuration,
and especially the annotation
`kubectl.kubernetes.io/last-applied-configuration` which contains the original
deployment specification.

Then it looks running `Pods` corresponding to the `Deployment` or `DaemonSet`
and looks the running container sha256 digest in `.status.containerStatuses[].imageID`.

Then it make a request to the registry to get the sha256 digest of the image,
eventually by using registry credentials stored used in the deployment.

Then it compare the sha256 digests and if they are not matching it `update` the
`Deployment` or `DaemonSet` to use the expected image with
`registry/image@sha256:....` notation.

Arguments
=========

::

    $ kubernetes-image-sync
    Usage of kubernetes-image-sync:
      -all-namespaces
            Check deployments and daemonsets on all namespaces (default false)
      -dry-run
            dry run mode. Do not update any deployments and daemonsets (default false)
      -field-selector string
            Kubernetes field-selector
            example: metadata.name=myapp
      -kubeconfig string
            kube config file (default "/home/phil/.kube/config")
      -l string
            Kubernetes labels selectors
            Warning: applies to Deployment and DaemonSet, not pods !
      -n string
            Check deployments and daemonsets in given namespace (default to current namespace)


Install and run
===============


From the command line
~~~~~~~~~~~~~~~~~~~~~

Assuming you have a working `~/.kube/config` file, just download and build the code::

  $ go get github.com/philpep/kubernetes-image-sync/...
  $ $(go env GOPATH)/bin/kubernetes-image-sync --help


From the docker image
~~~~~~~~~~~~~~~~~~~~~

Assuming you have a working `~/.kube/config` file::

  $ docker pull philpep/kubernetes-image-sync
  $ docker run --rm -it -v ~/.kube/config:/config philpep/kubernetes-image-sync --help

Inside the cluster
~~~~~~~~~~~~~~~~~~

You can run `kubernetes-image-sync` inside the cluster, for instance in a `CronJob` kubernetes object that runs every day.

See the `ServiceAccount <https://github.com/philpep/kubernetes-image-sync/blob/master/serviceaccount.yaml>`_
and `CronJob <https://github.com/philpep/kubernetes-image-sync/blob/master/cronjob.yaml>`_ objects.

::

  $ kubectl apply -f deploy/serviceaccount.yaml
  $ kubectl apply -f deploy/cronjob.yaml
