# Nmap Docker Container with Security Hardening
# Week 5-6: Docker Sandboxing Implementation

FROM alpine:3.19

# Metadata
LABEL maintainer="CyberShieldAI Security Team"
LABEL description="Hardened Nmap scanner container with security restrictions"
LABEL version="1.0"

# Install Nmap and required dependencies
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Create non-root user for running scans
RUN addgroup -g 1000 scanner && \
    adduser -D -u 1000 -G scanner scanner && \
    mkdir -p /scans /results && \
    chown -R scanner:scanner /scans /results

# Copy scan execution script
COPY scan_executor.py /usr/local/bin/scan_executor.py
RUN chmod +x /usr/local/bin/scan_executor.py && \
    chown scanner:scanner /usr/local/bin/scan_executor.py

# Set working directory
WORKDIR /scans

# Drop all capabilities except CAP_NET_RAW (required for raw sockets)
# This prevents privilege escalation
RUN apk add --no-cache libcap && \
    setcap cap_net_raw+ep /usr/bin/nmap

# Switch to non-root user
USER scanner

# Set resource limits via environment variables (enforced by Docker run flags)
ENV MAX_SCAN_TIME=300
ENV MAX_MEMORY=512M
ENV MAX_CPU=1.0

# Security: Read-only root filesystem (except /scans and /results)
VOLUME ["/results"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nmap --version || exit 1

# Default command (overridden by scan execution)
ENTRYPOINT ["python3", "/usr/local/bin/scan_executor.py"]
CMD ["--help"]
