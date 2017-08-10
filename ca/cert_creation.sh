ps -ef > noise.txt
date >> noise.txt
mkdir server_db
cd server_db
certutil -N --empty-password -d .
echo -e "5\n6\n7\ny\ny\n\ny\n" | certutil -S -s "CN=TLS-N Root CA"  -k ec -q secp256r1  -n tlsproofca -x -t "C,C,C" -1 -2 -d . -z ../noise.txt # 5,6,7,y,y,,y
ps -ef > ../noise.txt
date >> ../noise.txt
date "+%N" >> ../noise.txt
certutil -R -k ec -q secp256r1 -s "CN=tls-n.testserver,O=TLS-N,C=NN" -d . -u V -a -f pwd.txt -o cert.req -z ../noise.txt
openssl req -in cert.req -out cert.req2 -outform DER
certutil -C -i cert.req2 -o server.crt -c tlsproofca -f pwd.txt -d .
certutil -A -n tlsproofserver.com -t "u,u,u" -i server.crt -f pwd.txt -d .
cd ..
mkdir client_db
cp server_db/* client_db
cd client_db
certutil -D -d . -f pwd.txt -n tls-n.testserver
cd ..

