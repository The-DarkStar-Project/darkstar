# Use an official slim Python base
FROM python:3.13-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# Expose the FastAPI port
EXPOSE 8008

# Launch Uvicorn
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8008"]