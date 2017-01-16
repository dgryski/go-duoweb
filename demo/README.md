# Demo app

This program needs a "keys.yml" file with the following elements:

```yaml
---
ikey: duo_integration_key
skey: duo_secrect_key
akey: your_application_key # generate one with: openssl rand -hex 20
host: duo_api_host
```

Create one or copy and edit `keys-template.yml`

## Steps

- Create a new application in your Duo Security account. Get the keys and API hostname
- Edit the keys.yml file with your credentials (or copy and use `-c your-keys-file.yml`)
- Get the Duo Security Javascript file and put it in static/: `curl -L -o static/Duo-Web-v2.min.js https://raw.githubusercontent.com/duosecurity/duo_python/master/js/Duo-Web-v2.min.js`
- `go get` to get dependencies
- `go build` to build `demo`
- Run `./demo`
- Test it out!
