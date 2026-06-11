FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV UV_LINK_MODE=copy
ENV PATH="/root/.local/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        ffuf \
        git \
        gobuster \
        nikto \
        nmap \
        python3 \
        python3-venv \
        whois \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

WORKDIR /opt/spider

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY docs ./docs
COPY plan ./plan

RUN uv sync --all-extras --frozen \
    && uv cache clean \
    && find /opt/spider -type d -name "__pycache__" -prune -exec rm -rf {} +

CMD ["bash"]
