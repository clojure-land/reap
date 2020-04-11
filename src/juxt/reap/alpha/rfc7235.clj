;; Copyright © 2020, JUXT LTD.

(ns juxt.reap.alpha.rfc7235
  (:require
   [juxt.reap.alpha.combinators :as p]
   [juxt.reap.alpha.rfc7230 :refer [token OWS]]
   [juxt.reap.alpha.rfc5234 :as rfc5234 :refer [SP]]
   [juxt.reap.alpha.regex :as re]
   [juxt.reap.alpha.rfc7230 :as rfc7230])
  )

(set! *warn-on-reflection* true)


;; Authorization = credentials

;; BWS = <BWS, see [RFC7230], Section 3.2.3>
(def BWS OWS)

;; OWS = <OWS, see [RFC7230], Section 3.2.3>

;; Proxy-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS
;;  challenge ] )
;; Proxy-Authorization = credentials

;; WWW-Authenticate = *( "," OWS ) challenge *( OWS "," [ OWS challenge
;;  ] )

;; auth-param = token BWS "=" BWS ( token / quoted-string )
;; Don't think we need this
(defn auth-param-with-lookahead []
  (p/as-map
   (p/sequence-group
    (p/as-entry
     :name
     (p/pattern-parser (re-pattern (re/re-compose "(%s)%s=%s(?=%s)" token BWS BWS token)) 1))
    (p/as-entry
     :value
     (p/alternatives
      (p/pattern-parser (re-pattern token))
      (p/comp
       rfc7230/unescape-quoted-string
       (p/pattern-parser (re-pattern rfc7230/quoted-string) 1)))))))

(defn auth-param []
  (p/as-map
   (p/sequence-group
    (p/as-entry
     :name
     (p/pattern-parser (re-pattern (re/re-compose "(%s)%s=%s" token BWS BWS)) 1))
    (p/as-entry
     :value
     (p/alternatives
      (p/pattern-parser (re-pattern token))
      (p/comp
       rfc7230/unescape-quoted-string
       (p/pattern-parser (re-pattern rfc7230/quoted-string) 1)))))))

(comment
  (let [p (auth-param)
        m (re/input "foo = bar")]
    (p m)
    ))

(comment
  (let [p (p/sequence-group
           (p/pattern-parser (re-pattern (re/re-compose "(%s)%s=%s" token BWS BWS)) 1)
           (p/pattern-parser (re-pattern rfc7230/quoted-string)))]
    (p (re/input "foo=\"bar\"")
       #_(re/input "foo=bar"))
    ))


;; auth-scheme = token

;; token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )
;;  *"="
(def token68
  (re/re-compose "[%s]+=*" (rfc5234/merge-alternatives rfc5234/ALPHA rfc5234/DIGIT #{\- \. \_ \~ \+ \/})))

(def token68-lookahead
  (re/re-compose "%s(?=%s(?:,|$))" token68 OWS))

(comment
  (let [p
        (p/alternatives
         (p/as-entry
          :token68
          (p/pattern-parser
           (re-pattern token68-lookahead)))
         (p/as-entry
          :auth-params
          (p/comp
           vec
           (p/optionally
            (p/first
             (p/sequence-group
              (p/cons
               (p/alternatives
                (p/ignore
                 (p/pattern-parser
                  (re-pattern #",")))
                (auth-param))
               (p/zero-or-more
                (p/first
                 (p/sequence-group
                  (p/ignore
                   (p/pattern-parser
                    (re-pattern
                     (re/re-compose "%s%s" OWS ","))))
                  (p/optionally
                   (p/first
                    (p/sequence-group
                     (p/ignore (p/pattern-parser (re-pattern OWS)))
                     (auth-param))))))))))))))]
    (p (re/input "a"))
    #_(p (re/input "A a=b,c=d,B e=f,C abcdef==,D g=h,j=k"))
    ))



;; credentials = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param )
;;  *( OWS "," [ OWS auth-param ] ) ] ) ]

(defn credentials []
    (p/sequence-group
     (p/as-entry
      :auth-scheme
      (p/pattern-parser
       (re-pattern token)))
     (p/optionally
      (p/first
       (p/sequence-group
        (p/as-entry
         :space
         (p/pattern-parser
          (re-pattern
           (re/re-compose "%s" SP))))
        (p/alternatives
         (p/as-entry
          :token68
          (p/pattern-parser
           (re-pattern token68-lookahead)))
         (p/as-entry
          :auth-params
          (p/comp
           vec
           (p/optionally
            (p/first
             (p/sequence-group
              (p/cons
               (p/alternatives
                (p/pattern-parser
                 (re-pattern #","))
                (auth-param))
               (p/zero-or-more
                (p/first
                 (p/sequence-group
                  (p/pattern-parser
                   (re-pattern
                    (re/re-compose "%s%s" OWS ",")))
                  (p/optionally
                   (p/first
                    (p/sequence-group
                     (p/pattern-parser (re-pattern OWS))
                     (auth-param)))))))))))))))))))

;; credentials = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param )
;;  *( OWS "," [ OWS auth-param ] ) ] ) ]
(defn credentials []
  (p/as-map
   (p/sequence-group
    (p/as-entry
     :auth-scheme
     (p/pattern-parser
      (re-pattern token)))
    (p/optionally
     (p/first
      (p/sequence-group
       (p/ignore
        (p/pattern-parser
         (re-pattern
          (re/re-compose "%s" SP))))
       (p/alternatives
        (p/as-entry
         :token68
         (p/pattern-parser
          (re-pattern token68-lookahead)))
        (p/as-entry
         :auth-params
         (p/comp
          vec
          (p/optionally
           (p/first
            (p/sequence-group
             (p/cons
              (p/alternatives
               (p/ignore
                (p/pattern-parser
                 (re-pattern #",")))
               (auth-param))
              (p/zero-or-more
               (p/first
                (p/sequence-group
                 (p/ignore
                  (p/pattern-parser
                   (re-pattern
                    (re/re-compose "%s%s" OWS ","))))
                 (p/optionally
                  (p/first
                   (p/sequence-group
                    (p/ignore (p/pattern-parser (re-pattern OWS)))
                    (auth-param))))))))))))))))))))

;; challenge = auth-scheme [ 1*SP ( token68 / [ ( "," / auth-param ) *(
;;  OWS "," [ OWS auth-param ] ) ] ) ]
(defn challenge []
  (p/as-map
   (p/sequence-group
    (p/as-entry
     :auth-scheme
     (p/pattern-parser
      (re-pattern token)))
    (p/optionally
     (p/first
      (p/sequence-group
       (p/ignore
        (p/pattern-parser
         (re-pattern
          (re/re-compose "%s" SP))))
       (p/alternatives
        (p/as-entry
         :token68
         (p/pattern-parser
          (re-pattern token68-lookahead)))
        (p/as-entry
         :auth-params
         (p/comp
          vec
          (p/optionally
           (p/first
            (p/sequence-group
             (p/cons
              (p/alternatives
               (p/ignore
                (p/pattern-parser
                 (re-pattern #",")))
               (auth-param))
              (p/zero-or-more
               (p/first
                (p/sequence-group
                 (p/ignore
                  (p/pattern-parser
                   (re-pattern
                    (re/re-compose "%s%s(?!%s%s%s%s)" OWS "," OWS token SP token))))
                 (p/optionally
                  (p/first
                   (p/sequence-group
                    (p/ignore (p/pattern-parser (re-pattern OWS)))
                    (auth-param))))))))))))))))))))

(defn www-authenticate []
  (p/first
   (p/sequence-group
    (p/ignore
     (p/zero-or-more
      (p/pattern-parser
       (re-pattern
        (re/re-compose ",%s" OWS)))))
    (p/cons
     (challenge)
     (p/zero-or-more
      (p/first
       (p/sequence-group
        (p/ignore
         (p/pattern-parser
          (re-pattern
           (re/re-compose ",%s" OWS))))
        (p/optionally
         (p/first
          (p/sequence-group
           (p/ignore
            (p/pattern-parser
             (re-pattern OWS)))
           (challenge)))))))))))

(comment
  (let [p (www-authenticate)
        m (re/input "Newauth realm=\"apps\", type=1,   title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"")]
    (p m)))


(comment
  (let [p (www-authenticate)]
    (p (re/input "Bearer foo=bar,zip=qux,Basic aseifjasefa=,Bearer foo=bar"))))

;; quoted-string = <quoted-string, see [RFC7230], Section 3.2.6>

;; token = <token, see [RFC7230], Section 3.2.6>
;; token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )
;;  *"="
