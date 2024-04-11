## generate keys

```sh
    # service provider
    openssl genrsa -passout pass:secret -out sp.pem 4096 && openssl req -new -x509 -key sp.pem -out sp.cer -days 3650
    # identity provider
    openssl genrsa -passout pass:secret -out idp.pem 4096 && openssl req -new -x509 -key idp.pem -out idp.cer -days 3650
```