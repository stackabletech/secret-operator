# Description

This is an deployment helper for the Operator Lifecycle Manager which is usually present on OpenShift environments.

It is needed to work around various OLM restrictions.

What it does:

- creates Security Context Constraints just for this operator (maybe remove in the future)
- installs the Deployment and DaemonSet objects
- installs the operator webhook service
- installs the CSI driver and storage classes
- assigns it's own deployment as owner of all the namespaced objects to ensure proper cleanup
- patches the environment of all workload containers with any custom values provided in the Subscription object
- patches the resources of all workload containers with any custom values provided in the Subscription object
- patches the tolerations of all workload pods with any custom values provided in the Subscription object

## Usage

Users do not need to interact with the OLM deployer directly.

## How to Test

Requirements:

1. An OpenShift cluster.
2. Checkout the branch `secret-olm-deployer` from the [operators](https://github.com/stackabletech/openshift-certified-operators/tree/secret-olm-deployer) repo.
3. Clone the `stackable-utils` [repo](https://github.com/stackabletech/stackable-utils)

Install the secret operator using OLM and the `olm-deployer`. From the `stackable-utils` repo, run:

```bash
$ ./olm/build-bundles.sh -c $HOME/repo/stackable/openshift-certified-operators -r 24.11.0 -o secret -d
...
```

[!NOTE]
Bundle images are published to `oci.stackable.tech` so you need to log in there first.

The secret op and all it's dependencies should be installed and running in the `stackable-operators` namespace.

Run the integration tests:

```bash
$ ./scripts/run-tests --skip-operator secret --test-suite openshift
...
```
