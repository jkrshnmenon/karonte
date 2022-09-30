FROM badnack/karonte:latest as builder

FROM ubuntu:20.04
RUN apt -y update && apt -y upgrade
RUN apt -y install python3 python3-pip vim virtualenvwrapper sudo git
RUN useradd -ms /bin/bash karonte
RUN echo "karonte ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh" >> /home/karonte/.bashrc
USER karonte
WORKDIR /home/karonte/
COPY --from=builder /home/karonte/karonte/firmware /home/karonte/firmware
ADD config /home/karonte/config
ADD karonte /home/karonte/karonte
RUN pip3 install -U -r /home/karonte/karonte/requirements.txt
RUN mkdir /home/karonte/logs
RUN sudo chown -R karonte:karonte /home/karonte
RUN git clone https://github.com/ReFirmLabs/binwalk.git
WORKDIR /home/karonte/binwalk
RUN sudo python3 setup.py install
RUN pip install protobuf==3.20.0
ENV PATH="/home/karonte/.local/bin:$PATH"
CMD ["/bin/bash"]
