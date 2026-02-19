FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python init_db.py

# uploads dir needs to be writable
RUN chmod 777 uploads

EXPOSE 5000
CMD ["python", "app.py"]
