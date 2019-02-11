=====================
Kubernetes image sync
=====================

This project aims to ease continuous delivery of docker images in a kubernetes
cluster.

``kubernetes-image-sync`` looks for kubernetes ``Deployments`` and ``DaemonSets``
configuration and check if running ``Pods`` use the correct image sha256 digest
from the docker repository and update ``Deployments`` or ``DaemonSets`` to use the
correct image.

Users and/or CI might trigger rebuild of images (for instance in case of
security update). For a given docker image tag the actual content may be
updated, ``kubernetes-image-sync`` ensure you cluster is running the latest build.

How it works ?
==============

``kubernetes-image-sync`` looks for ``Deployments`` and ``DaemonSets`` configuration,
and especially the annotation
``kubectl.kubernetes.io/last-applied-configuration`` which contains the original
deployment specification.

Then it looks running ``Pods`` corresponding to the ``Deployment`` or ``DaemonSet``
and looks the running containers sha256 digests in ``.status.containerStatuses[].imageID``.

Then it make a request to the registry to get the sha256 digest of the image,
eventually by using registry credentials stored used in the deployment.

Then it compare the sha256 digests and if they are not matching it ``update`` the
``Deployment`` or ``DaemonSet`` to use the expected image with
``registry/image@sha256:....`` notation.

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


Example output
==============

::

    $ kubernetes-image-sync
    2019/02/11 17:55:21 checking Deployment/aptly:
    2019/02/11 17:55:21   aptly ok
    2019/02/11 17:55:21   nginx ok
    2019/02/11 17:55:22 checking Deployment/kibana:
    2019/02/11 17:55:22   kibana ok
    2019/02/11 17:55:22   nginx ok
    2019/02/11 17:55:22 checking Deployment/philpep.org-gitweb:
    2019/02/11 17:55:22   gitweb has to be updated to r.in.philpep.org/gitweb@sha256:ff00caed3525dec5d2e57ffe210a16630ed9d3c31bf611f2987533eba4a0cbbe
    2019/02/11 17:55:22   nginx ok
    2019/02/11 17:55:22 update Deployment/philpep.org images gitweb
    2019/02/11 17:55:22 checking DaemonSet/fluentd:
    2019/02/11 17:55:22   fluentd has to be updated to r.in.philpep.org/fluentd@sha256:6a92af8a9db2ca243e0eba8d401cec11b124822e15b558b35ab45825ed4d1f54
    2019/02/11 17:55:22 update DaemonSet/fluentd images fluentd


Install and run
===============


From the command line
~~~~~~~~~~~~~~~~~~~~~

Assuming you have a working ``~/.kube/config`` file, just download and build the code::

  $ go get github.com/philpep/kubernetes-image-sync/...
  $ $(go env GOPATH)/bin/kubernetes-image-sync --help


From the docker image
~~~~~~~~~~~~~~~~~~~~~

Assuming you have a working ``~/.kube/config`` file::

  $ docker pull philpep/kubernetes-image-sync
  $ docker run --rm -it -u $(id -u) -v ~/.kube/config:/config philpep/kubernetes-image-sync --help

Inside the cluster
~~~~~~~~~~~~~~~~~~

You can run ``kubernetes-image-sync`` inside the cluster, for instance in a ``CronJob`` kubernetes object that runs every day.

See the `ServiceAccount <https://raw.githubusercontent.com/philpep/kubernetes-image-sync/master/deploy/serviceaccount.yaml>`_
and `CronJob <https://raw.githubusercontent.com/philpep/kubernetes-image-sync/master/deploy/cronjob.yaml>`_ objects.

::

  $ kubectl apply -f deploy/serviceaccount.yaml
  $ kubectl apply -f deploy/cronjob.yaml
