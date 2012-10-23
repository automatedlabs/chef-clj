(ns chef-clj.auth-test
  (:use clojure.test
        chef-clj.auth))

(deftest sha1-digest-test
  (testing "sha1-digest"
    (is (java.util.Arrays/equals (sha1-digest "foo") 
           (.digest (java.security.MessageDigest/getInstance "sha1") (.getBytes "foo"))))))

(deftest sha1-base64-test
  (testing "sha1-base64"
    (is (= (sha1-base64 "foo") "C+7Hteo/D9vJXQ3UfzxbwnXaijM="))))

(deftest slice-by-test
  (testing "slice-by empty"
    (is (= (slice-by (.getBytes "") 5) [])))
  (testing "slice-by shorter than split"
    (is (= (slice-by (.getBytes "foo") 5) [(.getBytes "foo")]))))
