Simple SSH tunnel

## Run - Connect to proxy

```sh
tunnel ./sample_config.yaml
```

## Connect to server via proxy

```sh
# ssh internal_server_user_id@localhost -p localport_in_yaml
ssh root@localhost -p 16822
```

## Connect to private server
* Run - For example, [Dockge](https://github.com/louislam/dockge) is running on port 5001 inside the server, expose it to local port 5002
```sh
tunnel ./sample_dockge.yaml
```
* Then open web browser and visit http://localhost:5002

## Multiple tunnels
* See [sample_multiple.yaml](./sample_multiple.yaml).

## Build
* Prequiisite: [Go](https://golang.org/dl/) >= 1.24
```bash
make
```
