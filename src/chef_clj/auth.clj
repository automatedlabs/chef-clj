(ns chef-clj.auth
  (:require clojure.string
            [clojure.data.codec.base64 :as b64]))

(defn get-hash [type data]
  (.digest (java.security.MessageDigest/getInstance type) (.getBytes data) ))

(defn sha1-digest [data]
  (get-hash "sha1" data))

(defn sha1-base64 [data]
  (String. (b64/encode (sha1-digest data))))

(defn slice-by [data size]
  (loop [value data
         result []]
    (if (empty? value)
      (vec result)
      (recur (drop size value)
             (conj result (byte-array (take size value)))))))

(defn ruby-b64encode [value]
  (let [str-array (map #(String. %) (slice-by (b64/encode value) 60))]
    (apply str (interpose "\n" str-array))))

(defn canonical-time [timestamp] nil)

(def canonical-path-regex #"/+")
(def trailing-slash-regex #"/+$")

(defn canonical-path [path]
  (let [scrubbed-path (clojure.string/replace path canonical-path-regex "/")]
    (if (> (count scrubbed-path) 1)
        (clojure.string/replace scrubbed-path trailing-slash-regex "")
        scrubbed-path)))

(defn canonical-request [method, path, hashed-body, timestamp, userid] 
  (let [req-method (clojure.string/upper-case method)
        req-path (canonical-path path)
        req-timestamp (canonical-time timestamp)
        hashed-path (sha1-base64 path)]
    (str "Method:" req-method "\n"
         "Hashed Path:" hashed-path "\n"
         "X-Ops-Content-Hash:" hashed-body "\n"
         "X-Ops-Timestamp:" req-timestamp "\n"
         "X-Ops-UserId:" userid)))

(defn encrypt [user-key req] nil)

(defn sign-request [user-key method path body host timestamp user-id] 
  "Generate the headers for the Opscode authentication protocol."
  (let [req-timestamp (canonical-time timestamp)
        hashed-body (sha1-base64 (or body ""))
        headers {"x-ops-sign" "version=1.0"
                 "x-ops-userid" user-id
                 "x-ops-timestamp" req-timestamp
                 "x-ops-content-hash" hashed-body} 
        req (canonical-request method path hashed-body req-timestamp user-id)
        signature (ruby-b64encode(encrypt user-key req))]
    signature
    ;for i, line in enumerate(sig):
    ;    headers['x-ops-authorization-%s'%(i+1)] = line

    ))


    
    ;# Create RSA signature
    ;req = canonical_request(http_method, path, hashed_body, timestamp, user_id)
    ;sig = _ruby_b64encode(key.private_encrypt(req))
    ;for i, line in enumerate(sig):
    ;    headers['x-ops-authorization-%s'%(i+1)] = line
    ;return headers
