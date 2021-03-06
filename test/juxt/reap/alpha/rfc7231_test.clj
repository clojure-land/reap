;; Copyright © 2020, JUXT LTD.

(ns juxt.reap.alpha.rfc7231-test
  (:require
   [clojure.test :refer [deftest is are testing]]
   [juxt.reap.alpha.rfc7231 :as rfc7231]
   [juxt.reap.alpha.regex :as re]))

(deftest subtype-test
  (is (= "html" (re-matches (re-pattern rfc7231/subtype) "html"))))

(deftest parameter-test
  (testing "value"
    (is
     (=
      {:name "foo", :value "bar"}
      ((rfc7231/parameter)
       (re/input "foo=bar"))))
    (is
     (nil?
      ((rfc7231/parameter)
       (re/input "foo")))))

  ;; "The type, subtype, and parameter name tokens are
  ;; case-insensitive. Parameter values might or might not be
  ;; case-sensitive, depending on the semantics of the parameter
  ;; name." -- RFC 7231 Section 3.1.1.1
  (testing "case-insensitivity"
    (is
     (=
      ;; :name should be lower-case, but value unchanged.
      {:name "foo", :value "Bar"}
      ((rfc7231/parameter)
       (re/input "FOO=Bar"))))
    (is
     (nil?
      ((rfc7231/parameter)
       (re/input "foo")))))

  (testing "quoted-string"
    (is
     (=
      {:name "foo", :value "ba'r"}
      ((rfc7231/parameter)
       (re/input "foo=\"ba\\'r\"")))))

  (testing "optional parameter"
    (is
     (=
      {:name "foo"}
      ((rfc7231/optional-parameter)
       (re/input "foo"))))
    (is
     (=
      {:name "foo" :value "bar"}
      ((rfc7231/optional-parameter)
       (re/input "foo=bar"))))
    (is
     (=
      {:name "foo", :value "ba'r"}
      ((rfc7231/optional-parameter)
       (re/input "foo=\"ba\\'r\""))))))

(deftest content-language-test
  (is
   (= ["en" "de"]
      (map :language ((rfc7231/content-language) (re/input "en,de"))))
   (= [["en" "US"] ["de" nil]]
      (map (juxt :language :region)
           ((rfc7231/content-language) (re/input "en-US,de"))))))

(deftest media-range-without-parameters-test
  (is
   (= {:media-range "text/*"
       :type "text"
       :subtype "*"}
      ((rfc7231/media-range-without-parameters)
       (re/input "text/*")))))

(deftest media-range-test
  (is
   (=
    {:media-range "text/html"
     :type "text",
     :subtype "html",
     :parameters {"foo" "bar" "baz" "qu'x"}}
    ((rfc7231/media-range)
     (re/input "text/html;foo=bar;baz=\"qu\\'x\""))))

  ;; "The type, subtype, and parameter name tokens are
  ;; case-insensitive." -- RFC 7231 Section 3.1.1.1
  (testing "case insensitivity"
    (is
     (=
      {:media-range "text/html"
       :type "text"
       :subtype "html"
       :parameters {}}
      ((rfc7231/media-range)
       (re/input "TEXT/Html"))))))

(deftest qvalue-test
  (is (re-matches (re-pattern rfc7231/qvalue) "1"))
  (is (re-matches (re-pattern rfc7231/qvalue) "1.000"))
  (is (re-matches (re-pattern rfc7231/qvalue) "0.9"))
  (is (nil? (re-matches (re-pattern rfc7231/qvalue) "1.001")))
  (is (nil? (re-matches (re-pattern rfc7231/qvalue) "1.0000")))
  (is (nil? (re-matches (re-pattern rfc7231/qvalue) "0.1234"))))

;; TODO: weight tests

(deftest media-type-test
  (is (= {:type "text" :subtype "html" :parameters {}}
         ((rfc7231/media-type)
          (re/input "text/html"))))
  (is (= {:type "text" :subtype "html" :parameters {"foo" "bar" "zip" "qux"}}
         ((rfc7231/media-type)
          (re/input "text/html;foo=bar;ZIP=qux")))))

(deftest year-test
  (is (= "2020" ((rfc7231/year) (re/input "2020"))))
  (is (nil? ((rfc7231/year) (re/input "123")))))

;; TODO: Create a very cryptic Accept test designed to catch out all but the most compliant of parsers

(deftest accept-test
  (is
   (=
    [{:media-range "text/html"
      :type "text",
      :subtype "html",
      :parameters {"foo" "bar"}
      :qvalue 0.3
      :accept-ext [{:name "zip"} {:name "qux", :value "quik"}]}]
    ((rfc7231/accept)
     (re/input "text/html ;   foo=bar ;q=0.3;zip;\t qux=quik"))))

  (testing "Bad accept headers"
    (is
     (= '()
        ((rfc7231/accept)
         (re/input "text"))))
    (is
     (= '()
        ((rfc7231/accept)
         (re/input "text;text/html")))))

  ;; https://www.newmediacampaigns.com/blog/browser-rest-http-accept-headers
  (testing "Firefox"
    (is
     ((rfc7231/accept)
      (re/input "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))))

  (testing "Webkit"
    (is
     ((rfc7231/accept)
      (re/input "application/xml,application/xhtml+xml,text/html;q=0.9,\r\ntext/plain;q=0.8,image/png,*/*;q=0.5"))))

  (testing "IE"
    (is
     ((rfc7231/accept)
      (re/input "image/jpeg, application/x-ms-application, image/gif,\r\napplication/xaml+xml, image/pjpeg, application/x-ms-xbap,\r\napplication/x-shockwave-flash, application/msword, */*"))))

  (testing "Windows 7 Chrome"
    (is
     ((rfc7231/accept)
      (re/input "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")))))

(deftest accept-charset-test
  (is
   (= '({:charset "UTF-8", :qvalue 0.8}
        {:charset "shift_JIS", :qvalue 0.4})
      ((rfc7231/accept-charset)
       (re/input ", \t, , , UTF-8;q=0.8,shift_JIS;q=0.4")))))

(deftest accept-language-test
  (is
   (= [{:language-range "en-GB"}
       {:language-range "en-US" :qvalue 0.8}
       {:language-range "en" :qvalue 0.5}
       {:language-range "it" :qvalue 0.3}]
      ((rfc7231/accept-language)
       (re/input "en-GB,en-US;q=0.8,en;q=0.5,it;q=0.3"))))

  (are [input expected] (= expected ((rfc7231/accept-language) (re/input input)))
    ", , de ;q=0.7" [{:language-range "de" :qvalue 0.7}]

    "en-US ; q=1.0 ," [{:language-range "en-US", :qvalue 1.0}]

    "*;q=0.9 , fr;q=0.9" [{:language-range "*", :qvalue 0.9}
                          {:language-range "fr", :qvalue 0.9}]

    ", *" [{:language-range "*"}]

    ", , fr ;q=0.7" [{:language-range "fr", :qvalue 0.7}]

    "de;q=1.0" [{:language-range "de", :qvalue 1.0}]

    ", de;q=1.0" [{:language-range "de", :qvalue 1.0}]

    "en-US ;q=0.7 ," [{:language-range "en-US", :qvalue 0.7}]

    ", * ," [{:language-range "*"}]

    ", * ,en-US ;q=0.7 , *"
    [{:language-range "*"}
     {:language-range "en-US", :qvalue 0.7}
     {:language-range "*"}]))

(deftest accept-encoding-test
  (is
   (= '({:codings "gzip" :qvalue 0.3}
        {:codings "deflate"}
        {:codings "br"})
      ((rfc7231/accept-encoding)
       (re/input "gzip;q=0.3, deflate, br")))))
