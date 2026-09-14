FROM python:3.11-slim

WORKDIR /app

# Ensure non-root execution
RUN useradd -m mluser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app /app

# Secure ownership
RUN chown -R mluser:mluser /app
USER mluser

# Expose port (internal only via docker-compose)
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
