## Install the operator

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

