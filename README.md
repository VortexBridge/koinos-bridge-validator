# WARNING: THE CODE IN THIS REPOSITORY HAS NOT BEEN TESTED NOR AUDITED. IT IS NOT INTENDED FOR PRODUCTION.

# koinos-bridge-validator

## Building and running with docker

Requirements: `docker`. If you need to install docker on your VPC/server, you can do so on most systems like this:

```
curl -fsSL https://get.docker.com -o install-docker.sh
sudo sh install-docker.sh
```

First fill out your config.yml based on the example.

*FIME* - add more instructions here for filling in config.yml.

Make a new directory in your home directory called `.koinos` and put your config.yml in there - this will be mounted inside the built container at runtime.

Build the container:
```
docker build -t=koinos-bridge-validator:latest .
```

Run the container. This command will start a new container mapping your config.yml to inside the container at runtime. It is set to always restart so if the validator crashes, it will start back up (even if the VPC/server is rebooted). This assumes your API port will be 3020 and it maps the internal port of the container to the external port of your VPC/server.
```
docker run -d --name bridge-validator-1 -p 3020:3020 --restart always --mount type=bind,source="$HOME"/.koinos/config.yml,target=/root/.koinos/config.yml koinos-bridge-validator:latest
```

Follow the logs at any time (ctrl-c to exit, container will continue running):
```
docker logs -f bridge-validator-1
```

To stop the container:
```
docker stop bridge-validator-1
```

To start a stopped container:
```
docker start bridge-validator-1
```

If re-building the container after pulling in new source for an update, or if you need to run with new docker options, first remove the built container before running again:
```
docker rm bridge-validator-1
```

## Querying transactions from the validator

Query transactions status
```bash
curl -X GET \
  'http://localhost:3020/GetEthereumTransaction?TransactionId=0xc4400da5eb03fec6eb0450d1e02b694ea049d103e85ed0d10d568df2ee7800ad' \
  --header 'Accept: */*'

curl -X GET \
  'http://localhost:3020/GetKoinosTransaction?TransactionId=0x12203e1ba6fb09fd000e101337de7595c73357839a71c81ea5bb9997a03f294671e1' \
  --header 'Accept: */*'
```

## For testing / running without docker (for development)

command example:

Start a node
```bash
go run cmd/koinos-bridge-validator/main.go -d "$(pwd)/node_test"
```

Start test node 1
```bash
go run cmd/koinos-bridge-validator/main.go -d "$(pwd)/node_1"
```
Start test node 2
```bash
go run cmd/koinos-bridge-validator/main.go -d "$(pwd)/node_2"
```
