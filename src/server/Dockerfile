FROM    python:3.12-alpine

ENV     PYTHONUNBUFFERED=1

WORKDIR /home

# Install requirements
COPY    ["./server/requirements.txt", "./"]

RUN     pip install -r ./requirements.txt && rm ./requirements.txt

# Copy files
COPY    ["./_data/cert.pem", "./_data/key.pem", "./_data/"]

COPY    ["./_shared/protocol/injector.py", "./_shared/protocol/socks.py", "./_shared/protocol/"]

COPY    ["./_shared/base.py", "./_shared/"]

COPY    ["./server/config.py", "./server/"]

COPY    ["./server/main.py", "./"]

# Execute
CMD     ["python3", "./main.py"]
