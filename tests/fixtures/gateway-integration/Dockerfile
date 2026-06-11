FROM gcr.io/distroless/static-debian12:nonroot
COPY sunbeam-proxy /usr/local/bin/sunbeam-proxy
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/sunbeam-proxy"]
CMD ["serve"]
