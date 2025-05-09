FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /opt

RUN mkdir predator

ADD core ./predator/core
ADD conf ./predator/conf

COPY config.py.docker ./predator/config.py
COPY predator.py ./predator/predator.py
COPY predator.sh ./predator/predator.sh
COPY start_services.sh ./predator/start_services.sh

RUN mkdir -p ./predator/var/log
RUN mkdir -p ./predator/var/run

WORKDIR /tmp

COPY requirements_system.txt .
COPY requirements_python.txt .

RUN apt-get update && \
    cat requirements_system.txt | xargs apt-get install -y

RUN pip3 install -r requirements_python.txt

WORKDIR /opt/predator

RUN chmod +x ./predator.sh
RUN chmod +x ./start_services.sh

ENTRYPOINT ["/opt/predator/start_services.sh"]

EXPOSE 10000/tcp
EXPOSE 7777/tcp
