FROM ubuntu:bionic

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install git wget python3-pip pwgen
RUN git clone https://github.com/CIRCL/lookyloo.git
WORKDIR lookyloo

RUN pip3 install -r requirements.txt
RUN pip3 install -e .
RUN wget https://d3js.org/d3.v5.min.js -O lookyloo/static/d3.v5.min.js
RUN wget https://cdn.rawgit.com/eligrey/FileSaver.js/5733e40e5af936eb3f48554cf6a8a7075d71d18a/FileSaver.js -O lookyloo/static/FileSaver.js

RUN sed -i "s/SPLASH = 'http:\/\/127.0.0.1:8050'/SPLASH = 'http:\/\/splash:8050'/g" lookyloo/__init__.py
RUN secret_key=`pwgen -Bsv1 32`; sed -i "s/app.secret_key = 'changeme'/app.secret_key = '$secret_key'/g" lookyloo/__init__.py
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV FLASK_APP=lookyloo
EXPOSE 5000
ENTRYPOINT ["flask", "run", "--host=0.0.0.0"]
