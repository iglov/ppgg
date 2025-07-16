# ppgg
community bot manager

## Deploy

```bash
docker build --tag bender:v1 .
```

## Create & run
```bash
docker create -m 256M --restart always --env-file .env --name bender bender:v1
docker start bender

```
