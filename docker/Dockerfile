FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go ruby ruby-dev \
    libimage-exiftool-perl \
    git curl wget \
    && rm -rf /var/lib/apt/lists/*

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

# Go tools
RUN go install github.com/evilsocket/xray@latest || true
RUN go install github.com/k3170makan/GooDork@latest || true

# Ruby tools
RUN gem install vcsmap || true

# Clone remaining tools
WORKDIR /opt/tools
RUN git clone https://github.com/upgoingstar/datasploit.git || true \
    && git clone https://github.com/Smaash/snitch.git || true \
    && git clone https://github.com/ilektrojohn/creepy.git || true \
    && git clone https://github.com/arimogi/Google-Dorks.git || true

# Install the orchestrator
WORKDIR /app
COPY .. .
RUN pip3 install --break-system-packages -e .

ENTRYPOINT ["osint-orchestrator"]
