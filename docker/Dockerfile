FROM python:3.12-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml uv.lock README.md ./
COPY ldapgate/ ./ldapgate/
COPY assets/ ./assets/

RUN uv pip install --system .

EXPOSE 9000

CMD ["ldapgate", "serve", "--config", "/app/ldapgate.yaml"]
