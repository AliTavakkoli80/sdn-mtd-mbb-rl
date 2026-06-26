FROM alpine:latest

# 🛠️ FIX: Force Alpine to use HTTP instead of HTTPS to bypass TLS certificate errors
RUN sed -i 's/https/http/g' /etc/apk/repositories

# Install essential tools for Containernet, MTD, and RL evaluation
RUN apk add --no-cache \
    bash \
    dnsmasq \
    iperf3 \
    iputils \
    bind-tools \
    iproute2 \
    curl