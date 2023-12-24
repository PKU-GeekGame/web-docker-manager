FROM ustclug/debian:10
RUN apt update && apt -y upgrade && \
    apt install -y xinetd python3-openssl docker.io python3-pip && \
    rm -rf /var/lib/apt/lists/*
RUN pip3 install "requests<2.2.29" requests-unixsocket
COPY main.py /
COPY cert.pem /
COPY flaglib.py /
COPY db.py /
COPY redirect.html /
COPY socat /
RUN chmod +x /socat
COPY socat_static /
RUN chmod +x /socat_static
CMD ["python3", "main.py"]
