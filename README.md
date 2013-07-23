# pem-ssl

A Clojure library designed to create SSLContext from password less PEM certification file (Mostly used for APNS).

## Usage

Require

    (require '[pem-ssl.ssl :as ssl])

Create SSLContext from filepath, InputStream or KeyStore

    (ssl/ssl-context pem-file-path trust-manager-array)
    (ssl/ssl-context pem-input-stream trust-manager-array)
    (ssl/ssl-context keystore trust-manager-array)

Helpers:

    ; A TrustManager that trust any certification
    (ssl/trust-anything-manager)

    ; Create a KeyStore
    (ssl/create-keystore)

## License

Copyright © 2013 Linghua Zhang

Distributed under the Eclipse Public License, the same as Clojure.
