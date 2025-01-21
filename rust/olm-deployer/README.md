# How to test

Requirements:

1. An OpenShift cluster.
2. Checkout the branch `secret-olm-deployer` from the [operators](https://github.com/stackabletech/openshift-certified-operators/tree/secret-olm-deployer) repo.
3. Clone the `stackable-utils` [repo](https://github.com/stackabletech/stackable-utils)

Install the secret operator using OLM and the `olm-deployer`. From the `stackable-utils` repo, run:

```bash
$ ./olm/build-bundles.sh -c $HOME/repo/stackable/openshift-certified-operators -r 24.11.0 -o secret -d
...
```

The secret op and all it's dependencies should be installed and running in the `stackable-operators` namespace.

Run the integration tests:

```bash
$ ./scripts/run-tests --skip-operator secret --test-suite openshift
...
```
