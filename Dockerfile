FROM ubuntu:22.04
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install wget python3-dev git python3-venv python3-pip python-is-python3
RUN apt-get -y install libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 libxdamage1 libgbm1 libpango-1.0-0 libcairo2 libatspi2.0-0
RUN pip3 install poetry

WORKDIR lookyloo

COPY lookyloo lookyloo/
COPY tools tools/
COPY bin bin/
COPY website website/
COPY setup.py .
COPY pyproject.toml .
COPY poetry.lock .
COPY README.md .

RUN mkdir cache user_agents scraped

RUN echo LOOKYLOO_HOME="'`pwd`'" > .env
RUN poetry install
RUN poetry run playwright install
RUN poetry run tools/3rdparty.py
RUN poetry run tools/generate_sri.py
