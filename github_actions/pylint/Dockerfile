FROM python:3.7-alpine

RUN apk add --no-cache bash build-base gcc
RUN pip install --upgrade pip
RUN pip install pylint
RUN python --version ; pip --version ; pylint --version

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
