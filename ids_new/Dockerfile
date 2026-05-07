FROM python:3.11-slim

LABEL maintainer="network-ids"
LABEL version="2.0.0"
LABEL description="Advanced Network IDS - Industry Edition"

# Install system dependencies for Scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    iproute2 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application files
COPY network_ids_advanced.py .
COPY config.yaml .

# Directories for runtime output
RUN mkdir -p pcap_captures blocklists

# Expose Prometheus / REST API port
EXPOSE 9001

# Requires NET_ADMIN + NET_RAW capabilities
# docker run --cap-add NET_ADMIN --cap-add NET_RAW --network host ...
ENTRYPOINT ["python3", "network_ids_advanced.py"]
CMD ["-c", "config.yaml"]
