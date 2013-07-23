(ns pem-ssl.ssl
  (:import (java.security KeyStore Security) 
           (java.security.spec PKCS8EncodedKeySpec)
           (javax.net.ssl X509TrustManager KeyManagerFactory SSLContext)
           (java.io StringReader FileInputStream)
           (org.bouncycastle.openssl PEMReader) 
           (org.bouncycastle.jce.provider BouncyCastleProvider)))

(defn create-keystore []
  "Create a new KeyStore"
  (doto (KeyStore/getInstance (KeyStore/getDefaultType))
    (.load nil)))

(defn read-object [string]
  "Read key / cert from string"
  (Security/addProvider (new BouncyCastleProvider))
  (let [sr (StringReader. string)
        reader (PEMReader. sr)]
    (.readObject reader)))

(defn split-string [string begin end]
  "Parse data from string"
  (let [b (second (clojure.string/split string (re-pattern begin)))
        e (first (clojure.string/split b (re-pattern end)))]
    (str begin e end)))

(defn parse-pem! [pem-str keystore]
  "Parse pem bytes and set entry to keystore"
  (let [key-str (split-string pem-str "-----BEGIN RSA PRIVATE KEY-----" "-----END RSA PRIVATE KEY-----")
        pkey (read-object key-str)
        cert-str (split-string pem-str "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----") 
        cert (read-object cert-str)]
    (doto keystore
      (.setCertificateEntry "cert-alias" cert)
      (.setKeyEntry "key-alias" (.getPrivate pkey) (.toCharArray "") (into-array [cert])))))

(defn trust-anything-manager []
  "TrustManager that trusts anything"
  (proxy [X509TrustManager] []
    (getAcceptedIssuers [] nil)
    (checkClientTrusted [certs auth-type])
    (checkServerTrusted [certs auth-type])))

(defn keymanagers-from-keystore [keystore]
  "Get KeyManagers based on keystore"
  (let [factory (doto (KeyManagerFactory/getInstance "SunX509")
                  (.init keystore (.toCharArray "")))]
    (.getKeyManagers factory)))

(defmulti ssl-context (fn [x & _] (class x)))

(defmethod ssl-context java.lang.String [path trust-managers]
  "Get SSLContext from pem file and trust-managers"
  (with-open [fis (FileInputStream. path)]
    (ssl-context fis trust-managers)))

(defmethod ssl-context java.io.InputStream [pem-input-stream trust-managers]
  "Get SSLContext from PEM input stream and trust-managers"
  (let [keystore (create-keystore)
        tms (into-array [(trust-anything-manager)])
        string (slurp pem-input-stream)]
    (parse-pem! string keystore)
    (ssl-context keystore tms)))

(defmethod ssl-context java.security.KeyStore [keystore trust-managers]
  "Get SSLContext from keystore and trust-managers"
  (doto (SSLContext/getInstance "TLS")
    (.init (keymanagers-from-keystore keystore) trust-managers nil)))
