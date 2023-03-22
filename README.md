# picante


## Development

### Setup

To run in a local k8s cluster
* Add a Picante config in root of project starting with name `picante.yaml`

```yaml
metrics-address: ":8080"
log-level: info
development-mode: false
cosign:
  key-ref: ""
  ignore-tlog: false
  local-image: false
storage:
  api: http://localhost:9001/api/v1/bom
  api-key: myapikey
identity:
  issuer: https://myissuer.com
  project-id: myproject
```

* run

```bash
make dtrack && make local
```
