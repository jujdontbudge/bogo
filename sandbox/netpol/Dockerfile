# Holds the agent's network namespace and loads the default-deny rules into it.
FROM alpine:3.22
RUN apk add --no-cache nftables setpriv
COPY entrypoint.sh /usr/local/bin/netpol
ENTRYPOINT ["/usr/local/bin/netpol"]
