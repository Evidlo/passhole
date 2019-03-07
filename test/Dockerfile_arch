# test pip installation

FROM archlinux/base
MAINTAINER Evan Widloski "evan@evanw.org"

RUN pacman -Sy
RUN pacman --noconfirm -S gpgme python-pip gcc
RUN pacman --noconfirm -S bash
# fix locale
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# dont cache commands below this point
#   force rebuild using `docker build -t IMAGE --build-arg CACHEBUST=$(date) .`
ARG CACHEBUST=1

COPY . /home/passhole
WORKDIR /home/passhole

#FIXME: move this into ph
RUN mkdir /root/.config
RUN mkdir /root/.cache

RUN pip install .
RUN bash