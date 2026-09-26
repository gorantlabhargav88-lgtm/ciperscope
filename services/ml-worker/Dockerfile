FROM python:3.11-slim

WORKDIR /app

# Ensure non-root execution
RUN useradd -m mluser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app /app

# Secure ownership for app and cache volume
RUN chown -R mluser:mluser /app
RUN mkdir -p /home/mluser/.cache/huggingface/hub && chown -R mluser:mluser /home/mluser/.cache
ENV HF_HOME=/home/mluser/.cache/huggingface
ENV TRANSFORMERS_CACHE=/home/mluser/.cache/huggingface/hub
USER mluser

# Expose port (internal only via docker-compose)
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
