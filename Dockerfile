# Use Python 3.13 slim image as base
FROM python:3.13-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set working directory
WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpcap-dev \
    net-tools \
    iputils-ping \
    iproute2 \
    procps \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock README.md ./

RUN pip install uv

COPY khonshu/ ./khonshu/
COPY LICENSE ./

RUN uv pip install --system .

RUN useradd --create-home --shell /bin/bash khonshu && \
    chown -R khonshu:khonshu /app

USER khonshu

ENTRYPOINT ["khonshu"]

# Default command (can be overridden)
CMD ["--help"]
