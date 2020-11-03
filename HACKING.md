## Linting helm chart

    docker run -v (pwd):/home:z -ti --rm quay.io/helmpack/chart-testing sh -c "cd /home && ct lint --charts helm/ditto-operator/"

## Validate OLM manifest

    operator-courier verify --ui_validate_io olm/hawkbit-operator-bundle/

## Local build and installation

    docker build . -t quay.io/ctrontesting/ditto-operator:latest
    helm install ditto-operator ./helm/ditto-operator --set image.repository=quay.io/ctrontesting/ditto-operator --set image.tag=latest --set image.pullPolicy=Always --set openshift.enabled=true
