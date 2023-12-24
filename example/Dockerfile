FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt -y upgrade && \
    apt install -y python3 python3-pip

RUN pip install --no-cache-dir flask

COPY example.py /
COPY templates /templates

CMD [ "python3", "example.py" ]