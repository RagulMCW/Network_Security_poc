# EICAR Test String Signature
# This signature detects the EICAR antivirus test file in network traffic

signature eicar-malware {
    ip-proto == tcp
    payload /.*X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/
    event "EICAR malware test string detected"
}

signature eicar-http-post {
    ip-proto == tcp
    dst-port == 80, 8080, 5000
    http-request-body /.*X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/
    event "EICAR string in HTTP POST body"
}

signature eicar-http-get {
    ip-proto == tcp
    dst-port == 80, 8080, 5000
    http-reply-body /.*X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/
    event "EICAR string in HTTP response"
}

signature eicar-json-payload {
    ip-proto == tcp
    payload /.*\"content\":\"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\"/
    event "EICAR in JSON payload"
}
