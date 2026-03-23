# Stage 1: Build Go tools
FROM golang:1.22-bookworm AS go-builder
RUN go install github.com/evilsocket/xray@latest || true
RUN go install github.com/k3170makan/GooDork@latest || true

# Stage 2: Final image
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ruby ruby-dev \
    libimage-exiftool-perl \
    git curl wget \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder
COPY --from=go-builder /go/bin/ /usr/local/bin/

# Python tools
RUN pip3 install --break-system-packages \
    theHarvester \
    shodan \
    dork-cli \
    click \
    pydantic \
    pyyaml \
    rich \
    httpx \
    mcp

# recon-ng
RUN pip3 install --break-system-packages recon-ng || true

# SpiderFoot
RUN pip3 install --break-system-packages spiderfoot || true

# metagoofil
RUN pip3 install --break-system-packages metagoofil || true

# github-dorks
RUN pip3 install --break-system-packages github-dorks || true

# LinkedIn / People recon tools
RUN pip3 install --break-system-packages crosslinked sherlock-project || true

# Ruby tools
RUN gem install vcsmap || true

# Selenium deps for linkedin2username
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Clone remaining tools
WORKDIR /opt/tools
RUN git clone --depth 1 https://github.com/upgoingstar/datasploit.git || true \
    && git clone --depth 1 https://github.com/Smaash/snitch.git || true \
    && git clone --depth 1 https://github.com/ilektrojohn/creepy.git || true \
    && git clone --depth 1 https://github.com/arimogi/Google-Dorks.git || true \
    && git clone --depth 1 https://github.com/jobroche/InSpy.git || true \
    && git clone --depth 1 https://github.com/initstring/linkedin2username.git || true \
    && git clone --depth 1 https://github.com/mdsecactivebreach/LinkedInt.git || true

# InSpy and linkedin2username dependencies
RUN cd /opt/tools/InSpy && pip3 install --break-system-packages -r requirements.txt || true \
    && cd /opt/tools/linkedin2username && pip3 install --break-system-packages -r requirements.txt || true

# Install the orchestrator
WORKDIR /app
COPY . .
RUN pip3 install --break-system-packages -e .

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import src.mcp.server" || exit 1

ENTRYPOINT ["osint-orchestrator"]
