# Nikto Docker Container with Security Hardening
# Week 5-6: Docker Sandboxing Implementation

FROM alpine:3.19

# Metadata
LABEL maintainer="CyberShieldAI Security Team"
LABEL description="Hardened Nikto web scanner container with security restrictions"
LABEL version="1.0"

# Install Nikto and dependencies
RUN apk add --no-cache \
    perl \
    perl-net-ssleay \
    git \
    curl \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Clone Nikto from official repository
RUN git clone https://github.com/sullo/nikto /opt/nikto && \
    cd /opt/nikto && \
    git checkout master && \
    chmod +x /opt/nikto/program/nikto.pl

# Create non-root user for running scans
RUN addgroup -g 1001 webscanner && \
    adduser -D -u 1001 -G webscanner webscanner && \
    mkdir -p /scans /results && \
    chown -R webscanner:webscanner /scans /results /opt/nikto

# Copy scan execution script
COPY web_scan_executor.py /usr/local/bin/web_scan_executor.py
RUN chmod +x /usr/local/bin/web_scan_executor.py && \
    chown webscanner:webscanner /usr/local/bin/web_scan_executor.py

# Set working directory
WORKDIR /scans

# Switch to non-root user
USER webscanner

# Set resource limits via environment variables
ENV MAX_SCAN_TIME=600
ENV MAX_MEMORY=512M
ENV MAX_CPU=1.0
ENV NIKTO_PATH=/opt/nikto/program/nikto.pl

# Security: Read-only root filesystem (except /scans and /results)
VOLUME ["/results"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD perl /opt/nikto/program/nikto.pl -Version || exit 1

# Default command
ENTRYPOINT ["python3", "/usr/local/bin/web_scan_executor.py"]
CMD ["--help"]
