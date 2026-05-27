FROM python:3.13-slim-bookworm
LABEL authors="cats and dogs"
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY . /app
ENV UV_NO_DEV=1

WORKDIR /app
RUN uv sync --locked

ENTRYPOINT ["uv", "run", "main.py"]
CMD []