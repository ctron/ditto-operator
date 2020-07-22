## Linting helm chart

    docker run -v (pwd):/home:z -ti --rm quay.io/helmpack/chart-testing sh -c "cd /home && ct lint --charts helm/ditto-operator/"