# Playwright's official Python image: Python 3.12 plus Chromium and its system
# libraries, for the headless crawl (browser_crawl.py). Keep the tag in step with
# the playwright pin in requirements.txt.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Bind 0.0.0.0 so the API is reachable from other machines on the LAN
# (the laptop running the extension), not just localhost.
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
