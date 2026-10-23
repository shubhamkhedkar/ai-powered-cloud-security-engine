FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY cloudsec ./cloudsec
RUN pip install --no-cache-dir ".[dashboard]" && useradd -m scanner
USER scanner
ENTRYPOINT ["cloudsec"]
CMD ["--help"]
