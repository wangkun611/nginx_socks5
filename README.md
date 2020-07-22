Name
====
NGINX-based HttpDNS Server

Example nginx.conf
==================

    stream {
        upstream trojan {
            hash $socks5_dst_addr consistent;

            server s1.example.com:443;
            server s1.example.com:443;
            server s1.example.com:443;
            server s1.example.com:443;
        }

        log_format basic '$remote_addr [$time_local] '
                    '$protocol $socks5_dst_addr:$socks5_dst_port $status $bytes_sent $bytes_received '
                    '$upstream_addr $upstream_connect_time $upstream_bytes_sent $upstream_bytes_received '
                    '$session_time';

        access_log logs/nginx-access.log basic buffer=32k flush=20s;
        server {
            listen 9090;
            socks5_client_header_timeout 20s;
            socks5_upstream_password 123456;
            socks5_ssl_server_name off;
            socks5_ssl_trusted_certificate cacert-2020-01-01.pem;
            socks5_ssl_verify off;
            socks5_pass trojan://trojan;
        }
    }
