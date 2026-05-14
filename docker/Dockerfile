# ========== BUILD STAGE FOR GO/NUCLEI ==========
FROM golang:1.24-bullseye AS go-builder
ENV GOTOOLCHAIN=auto

# Install nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    mkdir -p /root/.config/nuclei && \
    /go/bin/nuclei -update-templates

# Clone the Wordfence templates
RUN export GITHUB_TEMPLATE_REPO=topscoder/nuclei-wordfence-cve && \
    /go/bin/nuclei -update-templates

# Install Katana, Gau, httpx for Asteroid
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/hahwul/dalfox/v2@latest

# ========== BUILD STAGE FOR RUST/RUSTSCAN ==========
FROM rust:1.81-slim-bullseye AS rust-builder

# Install RustScan with locked flag to use exact dependency versions
RUN cargo install rustscan --locked

# ========== BUILD STAGE FOR C TOOLS ==========
FROM ubuntu:22.04 AS c-builder

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

# Build THC-Hydra
RUN git clone https://github.com/vanhauser-thc/thc-hydra.git /tmp/thc-hydra && \
    cd /tmp/thc-hydra && \
    ./configure && \
    make && \
    make install

# Build massdns for BBOT DNS brute-force modules.
RUN git init /tmp/massdns && \
    cd /tmp/massdns && \
    git remote add origin https://github.com/blechschmidt/massdns.git && \
    git fetch --depth 1 origin HEAD && \
    git checkout FETCH_HEAD && \
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
    gcc \
    python3-pip \
    pipx \
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

# Create app directories
WORKDIR /app
RUN mkdir -p /app/bbot_output \
    /root/.config/nuclei /root/go/bin /root/.local/bin

# Install Python tooling
RUN pipx install bbot

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    chmod +x /opt/testssl/testssl.sh && \
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Install OWASP ZAP (latest stable release)
ARG ZAP_VERSION=2.16.0
RUN wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
        -O /tmp/zap.tar.gz && \
    tar xzf /tmp/zap.tar.gz -C /opt/ && \
    mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy && \
    ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap.sh && \
    rm /tmp/zap.tar.gz

# Copy compiled binaries from build stages
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /root/.config/nuclei /root/.config/nuclei/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/
COPY --from=rust-builder /usr/local/cargo/bin/rustscan /usr/local/bin/
COPY --from=c-builder /usr/local/bin/hydra* /usr/local/bin/
COPY --from=c-builder /usr/local/bin/massdns /usr/local/bin/

# Copy application code as a proper Python package. Compose bind mounts use the
# same path, so scanner-only containers can run without the source tree mounted.
COPY ./darkstar /app/darkstar
COPY ./logo_darkstar.png /app/logo_darkstar.png
COPY ./logo_sidn.png /app/logo_sidn.png
COPY ./logo_nlnet.png /app/logo_nlnet.png

RUN gcc -o /app/darkstar/tools/scripts/search_epss /app/darkstar/tools/scripts/search_epss.c

# Install Asteroid
RUN cd /app/darkstar && bash scanners/asteroid-install.sh

# Install Wapiti isolated from DarkStar and Asteroid Python dependencies.
RUN pipx install wapiti3

# Setup shell environment
RUN echo 'source ~/.bashrc' > /etc/bash.bashrc && \
    echo 'export PATH=$PATH:/root/.local/bin:/usr/local/bin' >> ~/.bashrc

# Change the CMD to start a bash shell
CMD ["/bin/bash"]
