# How to test

## Prepare a test namespace

This namespace is hard coded in the manifests created by olm.

    kubectl create ns test

## Install the objects that OLM would install

    kubectl create -n test -f rust/olm-deployer/tests/manifests/nginx/deployment.yaml

    kubectl create -f rust/olm-deployer/tests/manifests/olm/crds.yaml
    kubectl create -n test -f rust/olm-deployer/tests/manifests/olm/roles.yaml
    kubectl create -n test -f rust/olm-deployer/tests/manifests/olm/serviceaccount.yaml

## Finally run the olm-deployer

    cargo run -p olm-deployer run --dir rust/olm-deployer/tests/manifests/deployer --namespace test

## Cleanup

    kubectl delete ns test
    kubectl delete -f rust/olm-deployer/tests/manifests/olm/crds.yaml
    kubectl delete -n test -f rust/olm-deployer/tests/manifests/olm/roles.yaml
