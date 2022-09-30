FROM badnack/karonte:latest

RUN rm -rf /home/karonte/tool
COPY config /home/karonte/
COPY karonte /home/karonte/

CMD ["/bin/bash"]
