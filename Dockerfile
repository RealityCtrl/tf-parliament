FROM python:3.10.7-alpine3.16
WORKDIR /bin
COPY * /bin/
RUN pip install -r requirements.txt
RUN mkdir -p /github/workspace/
WORKDIR /github/workspace/
ENTRYPOINT ["/bin/tf-parliament.py"]
CMD ["."]
