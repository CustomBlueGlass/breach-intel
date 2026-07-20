FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Run as an unprivileged user rather than root: a container process that is
# compromised (e.g. via a dependency RCE) should not also hold root inside
# the container. Create a system user, hand it ownership of the app dir, drop
# to it before the process starts.
RUN useradd --system --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
