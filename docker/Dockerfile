# ========== BUILD STAGE FOR GO/NUCLEI ==========
FROM golang:1.25 AS go-builder
ENV GOTOOLCHAIN=auto

# Pin scanner versions so a fresh installation gets the same tested CLI and
# output contracts instead of whatever an upstream project publishes that day.
ARG NUCLEI_VERSION=v3.11.0
ARG KATANA_VERSION=v1.6.1
ARG GAU_VERSION=v2.2.4
ARG HTTPX_VERSION=v1.10.0
ARG DALFOX_VERSION=v2.13.0

# Install nuclei
RUN go install -v "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" && \
    mkdir -p /root/.config/nuclei && \
    /go/bin/nuclei -update-templates

# Clone the Wordfence templates
RUN export GITHUB_TEMPLATE_REPO=topscoder/nuclei-wordfence-cve && \
    /go/bin/nuclei -update-templates && \
    touch /root/nuclei-templates/.darkstar-template-update

# Install Katana, Gau, httpx for Asteroid
RUN CGO_ENABLED=1 go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
RUN go install "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}"
RUN go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
RUN go install "github.com/hahwul/dalfox/v2@${DALFOX_VERSION}"

# ========== BUILD STAGE FOR RUST/RUSTSCAN ==========
FROM rust:1.81-slim-bullseye AS rust-builder

# Install RustScan with locked dependencies and a tested CLI version.
ARG RUSTSCAN_VERSION=2.4.1
RUN cargo install rustscan --version "${RUSTSCAN_VERSION}" --locked

# ========== BUILD STAGE FOR C TOOLS ==========
FROM ubuntu:22.04 AS c-builder

ARG HYDRA_COMMIT=fd5fc2adb178bc23983b5c50e6558b48fcd75c1b
ARG MASSDNS_COMMIT=6bfa47197d78e68b79041d494e280174cb2d6ae1

# Install dependencies for THC-Hydra
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    git \
    build-essential \
    libssl-dev \
    libssh-dev \
    libidn11-dev \
    libpcre3-dev \
    libgtk2.0-dev \
    libmysqlclient-dev \
    libpq-dev \
    libsvn-dev \
    firebird-dev \
    libncurses5-dev \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build a reviewed Hydra revision. Retry transient GitHub/network failures,
# while keeping the source revision deterministic.
RUN git init /tmp/thc-hydra && \
    cd /tmp/thc-hydra && \
    git remote add origin https://github.com/vanhauser-thc/thc-hydra.git && \
    for attempt in 1 2 3 4 5; do \
        git fetch --depth 1 origin "${HYDRA_COMMIT}" && break; \
        [ "$attempt" -eq 5 ] && exit 1; \
        sleep "$((attempt * 2))"; \
    done && \
    git checkout --detach FETCH_HEAD && \
    ./configure && \
    make && \
    make install

# Build massdns for BBOT DNS brute-force modules.
RUN git init /tmp/massdns && \
    cd /tmp/massdns && \
    git remote add origin https://github.com/blechschmidt/massdns.git && \
    for attempt in 1 2 3 4 5; do \
        git fetch --depth 1 origin "${MASSDNS_COMMIT}" && break; \
        [ "$attempt" -eq 5 ] && exit 1; \
        sleep "$((attempt * 2))"; \
    done && \
    git checkout --detach FETCH_HEAD && \
    make && \
    install -m 0755 bin/massdns /usr/local/bin/massdns


# ========== FINAL RUNTIME STAGE ==========
FROM ubuntu:22.04

# Add cache busting argument
ARG CACHE_BUST=auto

SHELL ["/bin/bash", "-c"]

# Set environment variables
ENV TZ=Europe/Amsterdam \
    PATH="/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin"

# Install runtime dependencies + tools for Nikto, Wapiti, ZAP, testssl.sh
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    tzdata \
    gcc \
    python3-pip \
    python3-cairo \
    sudo \
    wget \
    nano \
    mariadb-client \
    nmap \
    nikto \
    curl \
    libssl-dev \
    libssh-dev \
    libpcre3 \
    libgtk2.0-0 \
    libmysqlclient21 \
    libpq5 \
    libsvn1 \
    libncurses5 \
    libfbclient2 \
    libidn12 \
    ca-certificates \
    git \
    openjdk-17-jre-headless \
    bash \
    openssl \
    dnsutils \
    bind9-dnsutils \
    bsdmainutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Ubuntu 22.04's pipx/argcomplete packages fail pip's dependency consistency
# check. Install one pinned, self-consistent pipx toolchain instead.
ARG PIPX_VERSION=1.16.2
RUN pip3 install --no-cache-dir "pipx==${PIPX_VERSION}"

# Create app directories
WORKDIR /app
RUN mkdir -p /app/bbot_output \
    /root/.config/nuclei /root/go/bin /root/.local/bin

# Install the BBOT major version whose CLI/output contract Darkstar targets.
# Pinning avoids silently rebuilding against a future breaking scanner release.
ARG BBOT_VERSION=3.0.0
RUN pipx install "bbot==${BBOT_VERSION}" && \
    pipx inject bbot tzdata

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Install a pinned testssl.sh revision with retry handling.
ARG TESTSSL_COMMIT=c4856bef7255fec85affb50ca112d68bfa9c28d5
RUN git init /opt/testssl && \
    cd /opt/testssl && \
    git remote add origin https://github.com/drwetter/testssl.sh.git && \
    for attempt in 1 2 3 4 5; do \
        git fetch --depth 1 origin "${TESTSSL_COMMIT}" && break; \
        [ "$attempt" -eq 5 ] && exit 1; \
        sleep "$((attempt * 2))"; \
    done && \
    git checkout --detach FETCH_HEAD && \
    chmod +x /opt/testssl/testssl.sh && \
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Install OWASP ZAP (latest stable release)
ARG ZAP_VERSION=2.16.0
RUN wget -q --tries=5 --retry-connrefused --waitretry=2 \
        "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
        -O /tmp/zap.tar.gz && \
    tar xzf /tmp/zap.tar.gz -C /opt/ && \
    mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy && \
    ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap.sh && \
    rm /tmp/zap.tar.gz

# Copy compiled binaries from build stages
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /root/.config/nuclei /root/.config/nuclei/
COPY --from=go-builder /root/nuclei-templates /root/nuclei-templates/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/
COPY --from=rust-builder /usr/local/cargo/bin/rustscan /usr/local/bin/
COPY --from=c-builder /usr/local/bin/hydra* /usr/local/bin/
COPY --from=c-builder /usr/local/bin/massdns /usr/local/bin/

# Copy only Asteroid before the expensive scanner install. The full app is
# copied after Wapiti so app/test-only changes do not invalidate scanner layers.
COPY ./darkstar/scanners/asteroid-install.sh /app/darkstar/scanners/asteroid-install.sh
COPY ./darkstar/scanners/asteroid /app/darkstar/scanners/asteroid

# Install Asteroid
ARG FEROXBUSTER_VERSION=2.13.1
ARG FEROXBUSTER_SHA256=7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80
ARG TRUFFLEHOG_VERSION=3.95.9
ARG TRUFFLEHOG_SHA256=f6d1106b85107d79527ed7a5b98b592beadd8b770dc3c9e8c1ad99e1b2cf127e
ARG ARJUN_VERSION=2.2.7
ARG WAPPALYZER_VERSION=2.0.2
RUN cd /app/darkstar && \
    FEROXBUSTER_VERSION="${FEROXBUSTER_VERSION}" \
    FEROXBUSTER_SHA256="${FEROXBUSTER_SHA256}" \
    TRUFFLEHOG_VERSION="${TRUFFLEHOG_VERSION}" \
    TRUFFLEHOG_SHA256="${TRUFFLEHOG_SHA256}" \
    ARJUN_VERSION="${ARJUN_VERSION}" \
    WAPPALYZER_VERSION="${WAPPALYZER_VERSION}" \
    bash scanners/asteroid-install.sh

# Install Wapiti isolated from DarkStar and Asteroid Python dependencies.
ARG WAPITI_VERSION=3.2.3
RUN pipx install "wapiti3==${WAPITI_VERSION}"

# Copy application code as a proper Python package. Compose bind mounts use the
# same path, so scanner-only containers can run without the source tree mounted.
COPY ./darkstar /app/darkstar
COPY ./logo_darkstar.png /app/logo_darkstar.png
COPY ./logo_sidn.png /app/logo_sidn.png
COPY ./logo_nlnet.png /app/logo_nlnet.png

RUN gcc -o /app/darkstar/tools/scripts/search_epss /app/darkstar/tools/scripts/search_epss.c

# Copy repository manifest/support files used by the in-container SBOM tests.
# Keep these after the heavyweight scanner installs so manifest-only changes do
# not invalidate Asteroid, Wapiti, ZAP, Go, or Rust build layers.
COPY ./requirements-dev.txt /app/requirements-dev.txt
COPY ./docker-compose.yaml /app/docker-compose.yaml
COPY ./docker /app/docker
COPY ./sql /app/sql
COPY ./openvas_api /app/openvas_api
COPY ./scripts /app/scripts
COPY ./docs/sbom /app/docs/sbom
COPY ./agents /app/agents

# Fail the build if apt- and pip-installed Python packages disagree. This
# catches image-only conflicts that the repository virtualenv cannot see.
RUN pip3 check

# Setup shell environment
RUN echo 'source ~/.bashrc' > /etc/bash.bashrc && \
    echo 'export PATH=$PATH:/root/.local/bin:/usr/local/bin' >> ~/.bashrc

# Change the CMD to start a bash shell
CMD ["/bin/bash"]
