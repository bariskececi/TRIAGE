FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3004
# scan an inventory then serve the risk quadrant:
#   docker run -p 3004:3004 -v $PWD/inventory.csv:/data/inv.csv triage \
#     sh -c "python run.py scan /data/inv.csv && python run.py dashboard"
CMD ["python", "run.py", "dashboard"]
