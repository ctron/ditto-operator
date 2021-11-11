# Releasing the next version

* Increment the version in `Cargo.toml`
* (Optional) Run `cargo update`
* Git Tag & Push -> builds container image

## OLM

* Create a new bundle
* Add the bundle to `olm/ditto-operator-bundle/ditto-operator.package.yaml`
  * Copy `<version>` directory
    * Update versions
    * Update the `replaces` field
* (Optional) Update CRDs
* Raise two PRs
  * Replace `HAS_OPENSHIFT=true` in one of the PRs

## Helm

* Copy files over the other Git repository:

      rsync -aLv helm/ditto-operator ~/git/helm-charts/charts/

* Commit and push
