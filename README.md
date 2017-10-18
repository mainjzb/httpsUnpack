# httpsUnpack
https receive, http send

编译方式  
gcc -Wall server.c -o server -lssl -lcrypto   

运行方式  
./server cacert.pem privkey.pem [dest_ip dest_port]  

生成：cacert.pem和privkey.pem  
openssl genrsa -out privkey.pem 2048  
openssl req -new -x509 -key privkey.pem -out cacert.epm -days 1095  

error:  
找不到openssl系列的头文件  
sudo apt-get install libssl-dev  
