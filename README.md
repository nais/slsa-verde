# picante

## Development

### Setup

To run in a local k8s cluster

* Add a [picante config](hack/picante-config-example.yaml) in root of project starting with
  name `picante`

```bash
make dtrack-up
```

wait for dp to be ready and run;

```bash
make local
```
