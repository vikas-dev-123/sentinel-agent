# For a Hugging Face "Docker" Space, or self-hosting.
# For a "Gradio" Space you do NOT need this file — Spaces runs app.py directly.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Hugging Face Spaces expects the app on port 7860.
EXPOSE 7860
ENV SENTINEL_MOCK=1

CMD ["python", "app.py"]
