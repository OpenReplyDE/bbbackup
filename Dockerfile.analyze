FROM rackspacedot/python37:latest

MAINTAINER Helge Staedtler "h.staedtler@reply.de"

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev

# Copy files needed to setup python installation

COPY ./requirements.txt /requirements.txt
COPY ./bbbackup.cfg /bbbackup.cfg
COPY ./bbbackup.py /bbbackup.py

WORKDIR /

RUN pip3 install --no-cache-dir -r requirements.txt

# COPY ./* /

CMD python3 /bbbackup.py --configuration bbbackup.cfg --no-notify
