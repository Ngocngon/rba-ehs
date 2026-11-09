FROM python:3.11-slim
WORKDIR /app
COPY . /app
EXPOSE 8765
ENV PORT=8765
ENV HOST=0.0.0.0
CMD ["python3", "server.py"]
