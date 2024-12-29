FROM python:3.14.0a3
WORKDIR /app/
COPY . .

RUN pip install cryptography

EXPOSE 8001 8011
CMD ["python", "./server.py"]