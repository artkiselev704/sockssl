FROM    python:3.12-alpine

ENV     PYTHONUNBUFFERED=1

WORKDIR /home

# Install requirements
COPY    ["./client/requirements.txt", "./"]

RUN     pip install -r ./requirements.txt && rm ./requirements.txt

# Copy files
COPY    ["./_shared/protocol/injector.py", "./_shared/protocol/socks.py", "./_shared/protocol/"]

COPY    ["./_shared/base.py", "./_shared/"]

COPY    ["./client/config.py", "./client/"]

COPY    ["./client/main.py", "./"]

# Execute
CMD     ["python3", "./main.py"]
