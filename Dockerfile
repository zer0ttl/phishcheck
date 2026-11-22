FROM ghcr.io/astral-sh/uv:0.11.21 AS uv
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
RUN uv sync --locked --no-dev --no-editable
USER phishcheck
EXPOSE 8000
ENTRYPOINT ["phishcheck"]
CMD ["serve", "--host", "0.0.0.0", "-p", "8000"]
