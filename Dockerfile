FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/satria

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl ca-certificates git docker.io bash gnupg unzip tar gzip \
    && rm -rf /var/lib/apt/lists/*

# Best-effort install scanner CLIs. If network is restricted during build,
# the app still works in SATRIA_DEMO_MODE=true.
RUN (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin) || true
RUN (curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin) || true
RUN (curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin) || true

COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY app ./app
COPY samples ./samples

RUN mkdir -p /data/reports

EXPOSE 8080
