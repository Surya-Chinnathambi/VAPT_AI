FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    docker.io \
    nmap \
    sqlmap \
    hydra \
    dnsutils \
    whois \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Go for Nuclei and Amass
RUN wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz && \
    rm go1.21.6.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Amass
RUN go install -v github.com/owasp-amass/amass/v4/...@latest

# Install Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/sublist3r && \
    pip install -r /opt/sublist3r/requirements.txt && \
    ln -s /opt/sublist3r/sublist3r.py /usr/local/bin/sublist3r

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/chroma_db /app/uploads /app/reports

# Expose port
EXPOSE 8000

# Default command (can be overridden in docker-compose)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
