FROM ghcr.io/astral-sh/uv:0.11.21 AS uv

FROM --platform=$BUILDPLATFORM python:3.13.12-slim-trixie AS styles
ARG BUILDARCH
RUN set -eu; \
    case "$BUILDARCH" in \
        amd64) asset=tailwindcss-linux-x64; digest=e47695cee3f0d90623a91f3939b08bdee610eb5ad99340adff9d4145b284d6cc ;; \
        arm64) asset=tailwindcss-linux-arm64; digest=ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad ;; \
        *) echo "Unsupported Tailwind build architecture: $BUILDARCH" >&2; exit 1 ;; \
    esac; \
    python -c 'import sys; from urllib.request import urlretrieve; urlretrieve(sys.argv[1], "/usr/local/bin/tailwindcss")' \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.5/$asset"; \
    printf '%s  %s\n' "$digest" /usr/local/bin/tailwindcss | sha256sum -c -; \
    chmod +x /usr/local/bin/tailwindcss
WORKDIR /app
COPY src/phishcheck/tailwind.css ./src/phishcheck/tailwind.css
COPY src/phishcheck/templates ./src/phishcheck/templates
RUN tailwindcss -i src/phishcheck/tailwind.css -o /tmp/phishcheck.css --minify

FROM python:3.13.12-slim-trixie
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update \
    && apt-get install -y --no-install-recommends libemail-address-perl libemail-outlook-message-perl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 phishcheck \
    && install -d -o phishcheck -g phishcheck /data
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never PATH="/app/.venv/bin:$PATH"
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY --from=styles /tmp/phishcheck.css ./src/phishcheck/static/phishcheck.css
RUN uv sync --locked --no-dev --no-editable
USER phishcheck
EXPOSE 8000
ENTRYPOINT ["phishcheck"]
CMD ["serve", "--host", "0.0.0.0", "-p", "8000"]
