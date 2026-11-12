FROM python:3.12-slim

RUN useradd --create-home appuser

WORKDIR /app

COPY analyzer.py reader.py ./
COPY fixtures ./fixtures

USER appuser

ENTRYPOINT ["python", "reader.py"]