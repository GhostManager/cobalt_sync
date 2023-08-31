FROM python:3.11-bullseye

WORKDIR /

COPY . .

RUN python3 -m pip install -r requirements.txt

CMD ["/bin/bash", "-c", "python3 -u cobalt_web.py"]
