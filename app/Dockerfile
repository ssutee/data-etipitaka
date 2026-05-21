FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/home/app
ENV APP_HOME=/home/app/web

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r app && useradd -r -g app app
RUN mkdir -p $APP_HOME/static $APP_HOME/media
WORKDIR $APP_HOME

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . $APP_HOME
RUN chown -R app:app $APP_HOME

USER app
ENTRYPOINT ["/home/app/web/entrypoint.sh"]
