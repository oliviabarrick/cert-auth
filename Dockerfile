FROM scratch

COPY ./cert-auth /cert-auth

ENTRYPOINT ["/cert-auth", "-bind-port", "8080"]
