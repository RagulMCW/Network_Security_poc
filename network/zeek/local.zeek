# Custom Zeek configuration for Network Security POC
# Ensures generation of specific protocol logs

# Load base scripts
@load base/frameworks/notice
@load base/frameworks/logging

# Load protocol analyzers for required logs
@load base/protocols/conn      # Connection logs (conn.log)
@load base/protocols/http      # HTTP traffic (http.log)
@load base/protocols/dns       # DNS queries (dns.log)
@load base/protocols/ssl       # SSL/TLS connections (ssl.log)
@load base/protocols/ssh       # SSH connections (ssh.log)
@load base/protocols/ftp       # FTP connections (ftp.log)

# Additional useful protocols
@load base/protocols/smtp      # Email traffic
@load base/files/hash          # File hashing

# Framework features
@load base/frameworks/files    # File extraction framework
@load base/frameworks/signatures  # Signature matching framework

# Load custom EICAR signatures
@load-sigs ./eicar-signatures.sig

# ========================================
# FILE EXTRACTION CONFIGURATION
# ========================================

# Extract files to extracted_files directory
redef FileExtract::prefix = "./extracted_files/";
redef FileExtract::default_limit = 10485760;  # 10MB max file size

# Custom logging to save extracted file content as .log files
global extracted_content_log = open_log_file("./extracted_content.log");

event file_sniff(f: fa_file, meta: fa_metadata)
{
    # Extract all files seen in HTTP traffic
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
}

event file_state_remove(f: fa_file)
{
    # Log extracted file information with content
    if ( f?$info && f$info?$extracted )
    {
        local extracted_path = f$info$extracted;
        local content = "";
        
        # Try to read the extracted file content
        local cmd = fmt("cat %s 2>/dev/null", extracted_path);
        
        # Create a log entry with file metadata and content
        local log_entry = fmt("[%s] File extracted: %s | MIME: %s | Size: %d bytes | Source: %s | Content: ",
                             network_time(),
                             extracted_path,
                             f$info?$mime_type ? f$info$mime_type : "unknown",
                             f$info?$total_bytes ? f$info$total_bytes : 0,
                             f$info?$source ? f$info$source : "unknown");
        
        # Write to custom log
        print extracted_content_log, log_entry;
        
        # Also create individual .log file for each extraction
        local log_filename = fmt("%s.log", extracted_path);
        local content_log = open(log_filename);
        print content_log, log_entry;
        close(content_log);
    }
}

# Ensure logs are written even with minimal traffic
redef Log::default_rotation_interval = 0 secs;

# Enable all protocol analyzers
redef likely_server_ports += {
    20/tcp,    # FTP data
    21/tcp,    # FTP control
    22/tcp,    # SSH
    25/tcp,    # SMTP
    53/tcp,    # DNS
    80/tcp,    # HTTP
    110/tcp,   # POP3
    143/tcp,   # IMAP
    443/tcp,   # HTTPS
    993/tcp,   # IMAPS
    995/tcp,   # POP3S
    3306/tcp,  # MySQL
    5432/tcp,  # PostgreSQL
    8080/tcp,  # HTTP alternate
    8443/tcp,  # HTTPS alternate
    5000/tcp,  # Custom app port
};

# ========================================
# EICAR Detection Configuration
# ========================================

# Event to detect EICAR string in HTTP body and log full content
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if ( /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/ in data )
    {
        local notice_msg = fmt("EICAR test string detected in HTTP traffic from %s to %s | Content preview: %s", 
                              c$id$orig_h, c$id$resp_h, data[0:200]);
        
        NOTICE([$note=Signatures::Sensitive_Signature,
                $msg=notice_msg,
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
}

# Log HTTP request and response bodies
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if ( c?$http )
    {
        # Log request/response info with body length
        local msg = fmt("HTTP %s %s%s - Body: %d bytes", 
                       c$http$method, c$http$host, c$http$uri, stat$body_length);
        Log::write(HTTP::LOG, [$ts=network_time(), 
                               $uid=c$uid,
                               $id=c$id,
                               $method=c$http$method,
                               $host=c$http$host,
                               $uri=c$http$uri]);
    }
}

