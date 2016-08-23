#生成私钥
openssl genrsa -out rsa_private_key.pem 2048

#创建证书请求
openssl req -new -out cert.csr -key rsa_private_key.pem
#自签署根证书,生成der格式证书文件
openssl x509 -req -in cert.csr -out rsa_public_key.der -outform der -signkey rsa_private_key.pem -days 3650

#生成rsa公钥
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

#生成pkcs8 PEM公钥
openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem