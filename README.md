## Install the operator

    helm install ditto-operator ./helm/ditto-operator

## MongoDB

    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm install mongodb bitnami/mongodb --set securityContext.enabled=false
