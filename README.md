# Imago

[![Build Status](https://travis-ci.org/philpep/imago.svg?branch=master)](https://travis-ci.org/philpep/imago)
[![Go Report Card](https://goreportcard.com/badge/github.com/philpep/imago)](https://goreportcard.com/report/github.com/philpep/imago)

This project aims to ease continuous delivery of docker images in a
kubernetes cluster.

[Imago](https://en.wikipedia.org/wiki/Imago) is the last stage of an
insect, it also refer to `image` and `go` (golang).

`imago` looks for kubernetes `Deployments`, `DaemonSets`, `StatefulSet` and `CronJobs`
configuration and update them to use the latest image sha256 digest from
the docker repository.

This is useful to handle the following cases:

  - image is rebuilt for security fixes
  - ensure all pods use exactly the same image
  - image is rebuilt by CI for continuous delivery

`imago` ensure your pods are running the latest build.

## How it works ?

`imago` looks for `Deployments`, `DaemonSets`, `StatefulSet` and `CronJob` configuration, get the
latest sha256 digest from registry and update containers specifications
to set image to the corresponding `registry/image@sha256:...` notation.
It track the original image specification in the `imago-config-spec`
annotation.

## Arguments

    $ imago
    Usage of imago:
      -all-namespaces
            Check deployments and daemonsets on all namespaces (default false)
      -check-pods
            check image digests of running pods (default false)
      -field-selector string
            Kubernetes field-selector
            example: metadata.name=myapp
      -kubeconfig string
            kube config file (default "~/.kube/config")
      -l string
            Kubernetes labels selectors
            Warning: applies to Deployment, DaemonSet, StatefulSet or CronJob, not pods !                                                                                                                  [15/832]
      -n string
            Check deployments and daemonsets in given namespaces (default to current namespace)
      -update
            update deployments and daemonsets to use newer images (default false)

By default, `imago` doesn't update your deployments, unless invoked with
`--update`.

The `--check-pods` is a less intrusive mode where update is done only if
one of the running pods doesn't run on latest digest image.

## Example output

    $ imago --update
    2019/02/11 17:55:21 checking default/Deployment/aptly:
    2019/02/11 17:55:21   aptly ok
    2019/02/11 17:55:21   nginx ok
    2019/02/11 17:55:22 checking default/Deployment/kibana:
    2019/02/11 17:55:22   kibana ok
    2019/02/11 17:55:22   nginx ok
    2019/02/11 17:55:22 update default/Deployment/philpep.org
    2019/02/11 17:55:22 checking DaemonSet/fluentd:
    2019/02/11 17:55:22   fluentd has to be updated from r.in.philpep.org/fluentd to r.in.philpep.org/fluentd@sha256:6a92af8a9db2ca243e0eba8d401cec11b124822e15b558b35ab45825ed4d1f54
    2019/02/11 17:55:22 update default/DaemonSet/fluentd


## Install and run

### From the command line

Assuming you have a working `~/.kube/config` file, just download and
build the code:

    $ go get github.com/philpep/imago/...
    $ $(go env GOPATH)/bin/imago --help

### From the docker image

Assuming you have a working `~/.kube/config` file:

    $ docker pull philpep/imago
    $ docker run --rm -it -u $(id -u) -v ~/.kube/config:/config philpep/imago --help

### Inside the cluster

You can run `imago` inside the cluster, for instance in a `CronJob`
kubernetes object that runs every day.

See the
[ServiceAccount](https://raw.githubusercontent.com/philpep/imago/master/deploy/serviceaccount.yaml)
and
[CronJob](https://raw.githubusercontent.com/philpep/imago/master/deploy/cronjob.yaml)
objects.

    $ kubectl apply -f deploy/serviceaccount.yaml
    $ kubectl apply -f deploy/cronjob.yaml
