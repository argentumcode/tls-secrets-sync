FROM gcr.io/distroless/static-debian11

COPY tls-secrets-sync /

EXPOSE 8888
ENV GCP_IAP_AUTH_LISTEN_PORT 8888

USER 1000:1000

ENTRYPOINT ["/tls-secrets-sync"]