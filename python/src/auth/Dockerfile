# Each instruction in a docker file creates a new layer in the image 
# Write the file carefully so that docker can cache layers as required

FROM python:3.10-slim-bullseye

RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
    build-essential default-libmysqlclient-dev \
    && pip install --no-cache-dir --upgrade pip

WORKDIR /app

COPY ./requirements.txt /app/

RUN pip install --no-cache-dir --requirement /app/requirements.txt

COPY . /app

# this doesn't do shit just more like documentation 
EXPOSE 5000

CMD ["python3","server.py"]