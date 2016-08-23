#VKRSA-迄今最好的iOS原生RSA库，性能高，使用简单
<p>最近研究JWE，发现在RSA环节出现各种坑(RSA代码从github其它库下载)，于是乎痛定思痛自己写了RSA的封装。</p>
## Demo运行效果
<p align="center"><img src="https://github.com/Vken-Chen/VKRSA/blob/master/capture.png" width="400"></p> 
## 使用
### 密钥生成
ken_gen.sh 脚本文件已经上传。内容为：
<pre>```
//生成私钥
openssl genrsa -out rsa_private_key.pem 2048
//创建证书请求
openssl req -new -out cert.csr -key rsa_private_key.pem
//自签署根证书,生成der格式证书文件
openssl x509 -req -in cert.csr -out rsa_public_key.der -outform der -signkey rsa_private_key.pem -days 3650
//生成rsa公钥
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
//生成pkcs8 PEM公钥
openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem
```</pre>

### 类说明

类 | 说明 
----|------
VKRSA | RSA算法封装类
VKRSAKey | RSA密钥操作类
NSError+VKRSA | NSError扩展，处理VKRSA相关错误

### VKRSA导出方法
<pre>
```
+ (NSData *)encryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error;
+ (NSData *)encryptData:(NSData *)data withPublicPem:(NSString*)pem ifError:(NSError**)error;
+ (NSData *)encryptString:(NSString*)string withPublicPem:(NSString*)pem ifError:(NSError**)error;
+ (NSData *)encryptData:(NSData *)data withPublicDer:(NSData*)der ifError:(NSError**)error;
+ (NSData *)encryptString:(NSString*)string withPublicDer:(NSData*)der ifError:(NSError**)error;
+ (NSData *)decryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error;
+ (NSData *)decryptData:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error;
+ (NSString* )decryptString:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error;

```
</pre>


### 加密
<li>用PEM证书对NSString加密
<pre>
```NSError *error = nil;
self.testStringEncryptResult = [VKRSA encryptString:self.testString withPublicPem:self.publicKeyPem ifError:&error];
if(error){
    NSLog(@"NSString PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSString PEM 加密成功");
}
```</pre>

<li>用PEM证书对NSData加密
<pre>
```
NSError *error = nil;
self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicPem:self.publicKeyPem ifError:&error];
if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData PEM 加密成功");
}
```</pre>

<li>用DER证书对NSString加密
<pre>
```
NSError *error = nil;
self.testStringEncryptResult = [VKRSA encryptString:self.testString withPublicDer:self.publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSString DER 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSString DER 加密成功");
}
```</pre>

<li>用DER证书对NSData加密
<pre>
```
NSError *error = nil;
self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicDer:self.publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSData DER 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData DER 加密成功");
}
```</pre>

### 解密
<li>用PEM证书对NSString解密
<pre>
```
NSError *error = nil;
NSString* result = [VKRSA decryptString:self.testStringEncryptResult withPrivatePem:self.privateKeyPem ifError:&error];
    if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData PEM 加密成功");
}
```</pre>

<li>用PEM证书对NSData解密
<pre>
```
NSError *error = nil;
self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicDer:self.publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData PEM 加密成功");
}
```</pre>

