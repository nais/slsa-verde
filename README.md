# picante

## Development

### Setup

To run in a local k8s cluster

* Add a [picante config](IdeaProjects/picante/hack/picante-config-example.yaml) in root of project starting with
  name `picante`

For local tests

```bash
make dtrack
```

Login on the dtrack GUI `admin:admin` and navigate to `administration.accessmanagement.teams` and create an api key and
add it to the [picante config](IdeaProjects/picante/hack/picante-config-example.yaml)

* run

```bash
make dtrack && make local
```
