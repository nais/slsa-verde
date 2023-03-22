# picante

## Development

### Setup

To run in a local k8s cluster

* Add a [Picante config](local/picante-config-example.yaml) in root of project starting with name `picante`

For integration tests

```bash
make dtrack
```

Login on the dtrack GUI and navigate to `administration.accessmanagement.teams` and create an api key and add it to the `picante` config

* run

```bash
make dtrack && make local
```
