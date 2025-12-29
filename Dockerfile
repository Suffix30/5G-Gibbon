FROM python:3.11-slim-bookworm

LABEL maintainer="NET"
LABEL description="5G-Gibbon: Advanced 5G/4G LTE Core Network Security Testing Toolkit"
LABEL version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    iptables \
    nftables \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ ./core/
COPY attacks/ ./attacks/
COPY defense/ ./defense/
COPY discovery/ ./discovery/
COPY enumeration/ ./enumeration/
COPY key_extraction/ ./key_extraction/
COPY protocol/ ./protocol/
COPY reporting/ ./reporting/
COPY utils/ ./utils/
COPY analysis/ ./analysis/
COPY tunneling/ ./tunneling/
COPY audit/ ./audit/
COPY red_team/ ./red_team/
COPY tests/ ./tests/
COPY run.py .
COPY docs/ ./docs/

RUN mkdir -p /app/reports /app/logs /app/data

RUN useradd --create-home --shell /bin/bash gibbon
RUN chown -R gibbon:gibbon /app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

ENTRYPOINT ["python", "run.py"]
CMD ["--help"]

