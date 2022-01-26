# Helm Chart for Stackable Operator for Stackable Secret Operator

This Helm Chart can be used to install Custom Resource Definitions and the Operator for Stackable Secret Operator provided by Stackable.


## Requirements

- Create a [Kubernetes Cluster](../Readme.md)
- Install [Helm](https://helm.sh/docs/intro/install/)


## Install the Stackable Operator for Stackable Secret Operator

```bash
# From the root of the operator repository
make compile-chart

helm install secret-operator deploy/helm/secret-operator
```


## Usage of the CRDs

The usage of this operator and its CRDs is described in the [documentation](https://docs.stackable.tech/secret-operator/index.html)

The operator has example requests included in the [`/examples`](https://github.com/stackabletech/secret-operator/tree/main/examples) directory.


## Links

https://github.com/stackabletech/secret-operator


