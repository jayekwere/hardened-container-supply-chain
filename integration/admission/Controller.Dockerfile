FROM ghcr.io/sigstore/policy-controller/policy-controller@sha256:0492bb264fb1d9bdc8e3f343ef542cc85b7dd7c7fd8d9524b453c2bd31a1d128 AS certificates
FROM scratch
ARG SOURCE_DATE_EPOCH=0
COPY --from=certificates /etc/ssl/certs/ /etc/ssl/certs/
COPY --chown=1000:1000 artifacts/controller/webhook /webhook
COPY artifacts/controller/LICENSE /licenses/policy-controller-LICENSE
USER 1000:1000
EXPOSE 8443
ENTRYPOINT ["/webhook"]
