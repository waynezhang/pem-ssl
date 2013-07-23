(ns pem-ssl.ssl-test
  (:require [clojure.test :refer :all]
            [pem-ssl.ssl :refer :all]))

(def not-nil? (complement nil?))
 
(def test-file "test/pem_ssl/test.pem")
(def test-key-file "test/pem_ssl/test_key.pem")
(def test-cert-file "test/pem_ssl/test_cert.pem")

(deftest create-keystore-test
  (testing "Create KeyStore"
    (is (not-nil? (create-keystore)))))

(deftest read-object-key-test
  (testing "Read key"
    (is (not-nil? (read-object (slurp test-key-file))))))

(deftest read-object-cert-test
  (testing "Read cert"
    (is (not-nil? (read-object (slurp test-cert-file))))))

(deftest split-string-test
  (testing "Parse data from string"
    (let [test-str "--- BEGIN TEST ---
                   here i am
                   --- END TEST ---"
          string (split-string (str "noisy noisy noisy" test-str "noisy noisy nosiy")
                               "--- BEGIN TEST ---"
                               "--- END TEST ---")]
      (is (= string test-str)))))

(deftest parse-pem!-test
  (testing "Parse pem"
    (let [string (slurp test-file)
          keystore (create-keystore)]
      (parse-pem! string keystore)
      (is (-> keystore
              (.aliases) 
              (.hasMoreElements))))))

(deftest trust-anything-manager-test
  (testing "Trust all manager"
    (is (not-nil? trust-anything-manager))))

(deftest keymanagers-from-keystore-test
  (testing "Get KEyManagers based on keystore"
    (let [keystore (create-keystore)]
      (is (not-nil? (keymanagers-from-keystore keystore))))))

(deftest ssl-context-keystore-test
  (testing "Create SSLContext from keystore"
    (let [string (slurp test-file)
          keystore (create-keystore)
          tms (into-array [(trust-anything-manager)])]
      (parse-pem! string keystore)
      (is (not-nil? (ssl-context keystore tms))))))

(deftest ssl-context-inputstream-test
  (testing "Create SSLContext from PEM inputstream"
    (with-open [r (java.io.FileInputStream. test-file)]
      (let [tms (into-array [(trust-anything-manager)])
            context (ssl-context r tms)]
        (is (not-nil? context))))))

(deftest ssl-context-file-test
  (testing "Create SSLContext from PEM file"
    (let [tms (into-array [(trust-anything-manager)])
          context (ssl-context test-file tms)]
      (is (not-nil? context)))))
