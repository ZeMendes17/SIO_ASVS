FROM python:3.11
WORKDIR /app_sec
ENV FLASK_APP=__init__.py
ENV FLASK_RUN_HOST=0.0.0.0
RUN apt update -y
RUN apt install gcc musl-dev wkhtmltopdf -y
COPY requirements.txt requirements.txt
RUN python -m venv venv
RUN venv/bin/pip install --upgrade pip && venv/bin/pip install -r requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt
EXPOSE 5000
COPY . .
CMD ["flask", "run"]