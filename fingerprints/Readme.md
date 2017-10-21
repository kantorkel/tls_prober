# GnuTLS

https://www.gnupg.org/ftp/gcrypt/gnutls/

`gnutls-serv`

# mbed TLS

https://tls.mbed.org/download-archive

`ssl_server`

# NSS

https://ftp.mozilla.org/pub/security/nss/releases/

# OpenSSL

https://www.openssl.org/source/old/

`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`

`openssl s_server -key key.pem -cert cert.pem -accept 44330 -www`
