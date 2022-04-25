FROM ubuntu:focal
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

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
RUN cp config/generic.json.sample config/generic.json
RUN cp config/modules.json.sample config/modules.json
RUN poetry install
RUN poetry run playwright install
RUN poetry run tools/validate_config_files.py --check
RUN poetry run tools/validate_config_files.py --update
RUN poetry run tools/3rdparty.py
RUN poetry run tools/generate_sri.py
