FROM gcr.io/distroless/static-debian11

COPY tls-secrets-sync /

USER 1000:1000

ENTRYPOINT ["/tls-secrets-sync"]