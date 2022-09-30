FROM badnack/karonte:latest

RUN rm -rf /home/karonte/karonte/tool
ADD config /home/karonte/karonte/config
ADD karonte /home/karonte/karonte/karonte

RUN mkdir /home/karonte/logs

CMD ["/bin/bash"]
