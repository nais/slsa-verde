

docker tag nginx ttl.sh/picanteapp1:6h
docker push ttl.sh/picanteapp1:6h

cosign attest --predicate authproxy.sbom.json --type cyclonedx --key cosign.key ttl.sh/picanteapp1:6h
