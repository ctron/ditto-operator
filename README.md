## Install the operator

You need to install the operator. Once you have installed the operator, you can create a new Ditto instance by
create a new custom resource of type `Ditto`.

### Using OperatorHub

The operator is available on [OperatorHub](https://operatorhub.io/operator/ditto-operator).

### Using Helm

You can also install the operator using [Helm](https://helm.sh/):

    helm install ditto-operator ./helm/ditto-operator

## MongoDB

You need to provide a MongoDB instance. You can easily deploy one with
the following Helm chart:

    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm install mongodb bitnami/mongodb --set securityContext.enabled=false --set mongodbRootPassword=admin123456 --set usePassword=false

## Create Ditto instance

Create a new Ditto instance:

~~~yaml
apiVersion: iot.eclipse.org/v1alpha1
kind: Ditto
metadata:
  name: test
spec:
  mongoDb:
    host: mongodb
~~~

