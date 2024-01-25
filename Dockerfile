FROM python

WORKDIR /application

COPY . /application

VOLUME /instance

RUN apt-get update && apt-get install -y python3 python3-pip

RUN pip install --upgrade pip 

RUN apt-get update && apt-get install -y python3 python3-pip libgmp-dev libmpc-dev

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "main.py"]