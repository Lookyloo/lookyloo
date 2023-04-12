FROM ubuntu:22.04
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install wget=1.21.* python3-dev=3.10.* git=1:2.34.* python3-venv=3.10.* python3-pip=22.0.* python-is-python3=3.9.* 
RUN apt-get -y install libnss3=2:3.68.* libnspr4=2:4.32-* libatk1.0-0=2.36.* libatk-bridge2.0-0=2.38.* libcups2=2.4.* libxkbcommon0=1.4.* libxdamage1=1:1.1.* libgbm1=22.2.* libpango-1.0-0=1.50.* libcairo2=1.16.* libatspi2.0-0=2.44.* 
RUN apt-get -y install libxcomposite1=1:0.4.* libxfixes3=1:6.0.* libxrandr2=2:1.5.* libasound2=1.2.* 
RUN pip3 install poetry

WORKDIR lookyloo

COPY lookyloo lookyloo/
COPY tools tools/
COPY bin bin/
COPY website website/
COPY pyproject.toml .
COPY poetry.lock .
COPY README.md .
COPY LICENSE .

RUN mkdir cache user_agents scraped

RUN echo LOOKYLOO_HOME="'`pwd`'" > .env
RUN poetry install
RUN poetry run playwright install
RUN poetry run tools/3rdparty.py
RUN poetry run tools/generate_sri.py
