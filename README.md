# writeup

https://b4bop4.notion.site/Stack-Canary-Lab-271ef1925963809ca7e7cb053148c9e8

# pwn-ubuntu_20.04

## Environment Description

This provides a base environment with `Ubuntu 20.04 GLIBC 2.31`, with `lib32z1` + `xinetd` packages pre-installed. Service forwarding is implemented based on `xinetd`, with the default exposed port set to 9999.

Implementation: When a player connects to the corresponding port (default port 9999, typically using `netcat`), the `program file` runs and the session is forwarded to the player's connection.

What the image does:
- Players connect to the container/target machine through the port
- xinetd service detects the connection and starts a `chroot` session
- `chroot` uses the parameter `--userspec=1000:1000 /home/ctf` to restrict the program's runtime account permissions and changes the program's runtime root directory environment location to `/home/ctf`, then starts the program in the restricted environment
- `xinetd` forwards the program session to the player's connection

## How to Use

Place the program file in the `./src` directory, and rename it to `attachment` so the image can locate the program.

If you need to change to your own filename, you must modify it in `./config/ctf.xinetd`, `./Dockerfile`, and `./service/docker-entrypoint.sh`.

After placing the program in the `./src` directory, execute:
```shell
docker build .
```
to start building the image.

Alternatively, after placing the program file, you can directly use the `docker-compose` file in `./docker/docker-compose.yml` to start a test container with one command:

```shell
cd ./docker
docker-compose up -d
```