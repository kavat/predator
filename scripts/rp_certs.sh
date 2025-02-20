openssl req -x509 -newkey rsa:4096 -keyout ./certs/pippo_a.key -out ./certs/pippo_a.pem -sha256 -days 3650 -nodes -subj "/C=IT/ST=Italy/L=Sesto Fiorentino/O=Predator/OU=Proxy/CN=pippo_a.org"

openssl req -x509 -newkey rsa:4096 -keyout ./certs/pippo_b.key -out ./certs/pippo_b.pem -sha256 -days 3650 -nodes -subj "/C=IT/ST=Italy/L=Sesto Fiorentino/O=Predator/OU=Proxy/CN=pippo_b.org"

openssl req -x509 -newkey rsa:4096 -keyout ./certs/rp_key.pem -out ./certs/rp_cert.pem -sha256 -days 3650 -nodes -subj "/C=IT/ST=Italy/L=Sesto Fiorentino/O=Predator/OU=Proxy/CN=rp"
