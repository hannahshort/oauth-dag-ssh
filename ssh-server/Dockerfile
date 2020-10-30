FROM rastasheep/ubuntu-sshd:18.04

RUN echo '* libraries/restart-without-asking boolean true' | debconf-set-selections

# RUN touch ~/.hushlogin

RUN apt-get update && \
	apt-get -y install curl unzip python python-requests python-qrcode libpam-python python-yaml rsyslog

RUN sed -ri 's/#UsePAM yes/UsePAM yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/#PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
RUN sed -ri 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
RUN sed -ri 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
RUN sed -ri 's/#ClientAliveInterval 0/ClientAliveInterval 1/g' /etc/ssh/sshd_config
RUN sed -ri 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
RUN sed -ri 's/#PrintLastLog yes/PrintLastLog no/g' /etc/ssh/sshd_config

COPY pam_oauth2_device pam_oauth2_device-master

WORKDIR /pam_oauth2_device-master

RUN mkdir /lib/security && \
 	cp src/pam_oauth2_device.py /lib/security/

COPY config_python.yml /lib/security/config.yml
COPY sshd_python /etc/pam.d/sshd

RUN chmod -x /etc/update-motd.d/*
RUN rm /etc/legal

CMD service rsyslog start && /usr/sbin/sshd -D
