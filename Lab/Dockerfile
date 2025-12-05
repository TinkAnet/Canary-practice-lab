FROM ubuntu:20.04


LABEL auther_template="CTF-Archives"



RUN apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd

# create ctf user and set workdir
RUN useradd -m ctf
WORKDIR /home/ctf

# copy related libs and configure environment
RUN cp -R /usr/lib* /home/ctf

# configure special device nodes
RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

# deploy limited bin commands
RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
    cp /usr/bin/timeout /home/ctf/bin

# deploy xinetd service 
COPY ./config/ctf.xinetd /etc/xinetd.d/ctf
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

# copy entrypoint script
COPY ./service/docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

# copy challenge files
COPY ./src/attachment /home/ctf/attachment

# initialize flag
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    touch /home/ctf/flag && \
    chmod 744 /home/ctf/flag


# EXPOSE 9999

# final entrypoint
ENTRYPOINT ["/bin/bash","/docker-entrypoint.sh"]
