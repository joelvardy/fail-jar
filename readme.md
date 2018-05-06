# Fail Jar

This is not _production quality_ code. It could be cleaned up and improved quite a lot. But it will serve it's purpose for a few months.

### Building

```
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .
docker build -t 527669730630.dkr.ecr.eu-west-1.amazonaws.com/joelvardy/fail-jar:master -f ./Dockerfile .
```

### Pushing

```
$(aws ecr get-login --region=eu-west-1 --no-include-email --profile=joelvardy)
docker push 527669730630.dkr.ecr.eu-west-1.amazonaws.com/joelvardy/fail-jar:master
```

### Running locally

```
docker run -it -p 80:80 527669730630.dkr.ecr.eu-west-1.amazonaws.com/joelvardy/fail-jar:master
```

### Testing

```
curl -v -X POST -d "{\"payload\": {\"vcs_type\": \"github\",\"reponame\": \"joelgonewild.com\",\"failed\": true,\"username\": \"joelvardy\",\"build_num\": 7,\"branch\": \"master\"}}" HOST/build
```

### Environment variables

```
CIRCLECI_TOKEN=
MONZO_CLIENT_ID=
MONZO_CLIENT_SECRET=
MONZO_OAUTH_CALLBACK_URL=HOST/monzo/login/callback
MONZO_JOEL_VARDY_USER_ID=
MONZO_POT_ID=
MONZO_ACCOUNT_ID=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
```
