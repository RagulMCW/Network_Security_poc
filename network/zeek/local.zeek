# Custom Zeek configuration for Network Security POC
# Ensures generation of specific protocol logs and malware hash tracking

@load base/frameworks/notice
@load base/frameworks/logging
@load base/frameworks/files
@load base/frameworks/signatures

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp
@load base/files/hash

# Load custom signatures
@load-sigs ./eicar-signatures.sig

# ========================================
# CONFIGURATION
# ========================================

redef FileExtract::prefix = "/app/zeek_logs/extracted_files/";
redef FileExtract::default_limit = 10485760;
redef Log::default_rotation_interval = 0 secs;

redef likely_server_ports += {
    20/tcp, 21/tcp, 22/tcp, 25/tcp, 53/tcp, 80/tcp, 
    110/tcp, 143/tcp, 443/tcp, 993/tcp, 995/tcp, 
    3306/tcp, 5432/tcp, 8080/tcp, 8443/tcp, 5000/tcp
};

# Add custom field to files.log
redef record Files::Info += {
    header_hash: string &log &optional;
};

# Global store for hashes from headers
global http_file_hashes: table[string] of string;

# ========================================
# EVENT HANDLERS
# ========================================

# 1. Capture Hash from HTTP Headers
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && /X-ORIGINAL-HASH/i in name )
    {
        http_file_hashes[c$uid] = value;
    }
}

# 2. Associate Hash with File and Enable Extraction
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SHA1);
    Files::add_analyzer(f, Files::ANALYZER_SHA256);

    if ( c$uid in http_file_hashes )
    {
        f$info$header_hash = http_file_hashes[c$uid];
    }
}

# 3. EICAR and POST Body Detection
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    # EICAR Detection
    if ( /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/ in data )
    {
        local notice_msg = fmt("EICAR detected from %s to %s", c$id$orig_h, c$id$resp_h);
        NOTICE([$note=Signatures::Sensitive_Signature, $msg=notice_msg, $conn=c, $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }

    # POST Body Extraction (for large uploads)
    if ( is_orig && c?$http && c$http?$method && c$http$method == "POST" && length > 1000 )
    {
        local fname = fmt("%s/post_body_%s.bin", FileExtract::prefix, c$uid);
        local f = open(fname);
        print f, data;
        close(f);
    }
}

# 4. Log HTTP Details
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if ( c?$http )
    {
        Log::write(HTTP::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $method=c$http$method, $host=c$http$host, $uri=c$http$uri]);
    }
}

