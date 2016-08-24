#VKRSA-迄今最好的iOS原生RSA库，性能高，使用简单
<p>最近研究JWE，发现在RSA环节出现各种坑(RSA代码从github其它库下载)，于是乎痛定思痛自己写了RSA的封装。</p>
## 1. Demo运行效果
<p align="center"><img src="https://github.com/Vken-Chen/VKRSA/blob/master/capture.png" width="400"></p> 
## 2. 使用步骤
<p>使用VKRSAOperator类进行加解密相关操作</p>
<li>step 1.密钥初始化</li>
<li>step 2.解密或者解密</li>
### 2.1 密钥初始化
如果对密钥和证书不懂，请看<a href='http://www.jianshu.com/p/6927fe6f9813'>证书编码以及文件格式汇总</a>
#### 2.1.1 公钥初始化
<p>说明：如果只做加密，只需要初始化公钥</p>
<li>DER格式的公钥</li>
<pre>
NSString* file = [[NSBundle mainBundle]pathForResource:@"rsa_public_key" ofType:@"der"];
NSString* publicKeyDer = [NSData dataWithContentsOfFile:file];
BOOL publickReady = [[VKRSAOperator defaultOperator]setupPublicKeyWithDER:publicKeyDer];
if(publickReady)
{
    NSLog(@"VKRSAOperator DER 公钥创建成功);
}else{
    NSLog(@"VKRSAOperator DER 公钥创建失败，原因：%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}
</pre>

<li>PEM格式的公钥</li>
<pre>
NSString* file = [[NSBundle mainBundle]pathForResource:@"rsa_public_key" ofType:@"pem"];
NSString* publicKeyPem = [NSData dataWithContentsOfFile:file];
BOOL publickReady = [[VKRSAOperator defaultOperator]setupPublicKeyWithPEM: publicKeyPem];
if(publickReady)
{
    NSLog(@"VKRSAOperator PEM 公钥创建成功);
}else{
    NSLog(@"VKRSAOperator PEM 公钥创建失败，原因：%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}
</pre>
#### 2.1.2 私钥初始化
<p>说明：如果只做解密，只需要初始化私钥。<br>
目前私钥只支持pkcs8格式的PEM私钥文件，后续升级。<br>
为什么私钥没有DER格式？目前DER格式一般来说只用于公钥，对外传播。</p>
<li>PEM格式的私钥</li>
<pre>
NSString* file = [[NSBundle mainBundle]pathForResource:@"rsa_private_key_pkcs8" ofType:@"pem"];
NSString* privateKeyPem = [NSData dataWithContentsOfFile:file];
BOOL privateKeyReady = [[VKRSAOperator defaultOperator]setupPrivateKeyWithPEM: privateKeyPem];
if(privateKeyReady)
{
    NSLog(@"VKRSAOperator PEM 私钥创建成功);
}else{
    NSLog(@"VKRSAOperator PEM 私钥创建失败，原因：%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}
</pre>
### 2.2 加密
<li> 加密NSData </li>
<pre>
NSData* data = ...;
NSData* encryptData = [[VKRSAOperator defaultOperator]encryptData: data];
if(encryptData == nil)
{
	NSLog(@"VKRSAOperator NSData DER 加密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}else{
	NSLog(@"VKRSAOperator NSData DER 加密成功");
}
</pre>
<li> 加密NSString(UTF8编码) </li>
<pre>
NSString* string = ...;
NSData* encryptData= [[VKRSAOperator defaultOperator]encryptUTF8String: string];
if(encryptData == nil)
{
	NSLog(@"VKRSAOperator NSData DER 加密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}else{
	NSLog(@"VKRSAOperator NSData DER 加密成功");
}
</pre>

### 2.3 解密
<li> 解密到NSData </li>
<pre>
NSData* encryptData = ...;
NSData* decryptData = [[VKRSAOperator defaultOperator]decryptData: encryptData];
if(decryptData == nil){
	NSLog(@"VKRSAOperator NSData 解密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}else{
	NSLog(@"VKRSAOperator NSData 解密成功);
}
</pre>
<li> 解密到NSString(UTF8编码) </li>
<pre>
NSData* encryptData = ...;
NSString* decryptUTF8String = [[VKRSAOperator defaultOperator]decryptUTF8String: encryptData];
if(decryptUTF8String == nil){
	NSLog(@"VKRSAOperator NSString 解密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
}else{
	NSLog(@"VKRSAOperator NSString 解密成功);
}
</pre>

## 3. 高级使用
### 3.1 密钥生成
ken_gen.sh 脚本文件已经上传。内容为：
<pre>
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
</pre>

### 3.2 类说明

类 | 说明 
----|------
VKRSA | RSA算法封装类
VKRSAKey | RSA密钥操作类
VKRSAOperator | 封装的RSA操作单例，简单使用只需要使用该类
NSError+VKRSA | NSError扩展，处理VKRSA相关错误

### 3.3 VKRSA使用
#### 3.3.1 VKRSA导出函数
<pre>
+ (NSData *)encryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error;
+ (NSData *)encryptData:(NSData *)data withPublicPem:(NSString*)pem ifError:(NSError**)error;
+ (NSData *)encryptString:(NSString*)string withPublicPem:(NSString*)pem ifError:(NSError**)error;
+ (NSData *)encryptData:(NSData *)data withPublicDer:(NSData*)der ifError:(NSError**)error;
+ (NSData *)encryptString:(NSString*)string withPublicDer:(NSData*)der ifError:(NSError**)error;
+ (NSData *)decryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error;
+ (NSData *)decryptData:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error;
+ (NSString* )decryptString:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error;
</pre>

#### 3.3.2 VKRSA加密
<li>用PEM证书对NSString加密</li>
<pre>
NSError *error = nil;
self.testStringEncryptResult = [VKRSA encryptString:self.testString withPublicPem:self.publicKeyPem ifError:&error];
if(error){
    NSLog(@"NSString PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSString PEM 加密成功");
}
</pre>

<li>用PEM证书对NSData加密</li>
<pre>
NSError *error = nil;
self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicPem:self.publicKeyPem ifError:&error];
if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData PEM 加密成功");
}
</pre>

<li>用DER证书对NSString加密</li>
<pre>
NSError *error = nil;
self.testStringEncryptResult = [VKRSA encryptString:self.testString withPublicDer:self.publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSString DER 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSString DER 加密成功");
}
</pre>

<li>用DER证书对NSData加密</li>
<pre>
NSError *error = nil;
self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicDer:self.publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSData DER 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData DER 加密成功");
}
</pre>

#### 3.3.3 VKRSA解密
<li>用PEM证书对NSString解密</li>
<pre>
NSError *error = nil;
NSString* result = [VKRSA decryptString:self.testStringEncryptResult withPrivatePem:self.privateKeyPem ifError:&error];
    if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData PEM 加密成功");
}
</pre>

<li>用PEM证书对NSData解密</li>
<pre>
NSError *error = nil;
self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicDer:self.publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
}else{
    NSLog(@"NSData PEM 加密成功");
}
</pre>
### 3.4 异常处理
#### 3.4.1 VKRSAOperator异常
1.如果程序运行错误，错误信息会记录在VKRSAOperator的NSError中<br>
``` @property(nonatomic,strong,readonly)    NSError*    lastError; ```<br>
调用者可以通过直接读取lastError提取相关的错误信息。<br>
2.外部调用者也可以通过 lastErrorDescription 方法获取错误
```- (NSString*)lastErrorDescription;```
```[[VKRSAOperator defaultOperator] lastErrorDescription];```
#### 3.4.2 其他异常
VKRSA、VKRSAKey类的异常都需要传入NSError对象接收错误，如下代码：<br>
<pre>
NSError *error = nil;
id result = [VKRSA encryptData:data withPublicDer:publicKeyDer ifError:&error];
if(error){
    NSLog(@"NSData PEM 加密错误:%@", error.localizedDescription );
    ...
}
</pre>

### 4.总结
该代码的实现是依靠Security.Framework提供的API来实现。Security.Framework提供的是X.509标准证书格式的加解密，API就是 SecKeyEncrypt && SecKeyDecrypt。这组API依赖的参数比较特殊，特别是key，一定是SecKeyRef格式。SecKeyRef 的来源有两处，一个PEM，一个是DER。目前大多用的PEM，PEM的效率其实相对较低。<br>通常情况下，应该是这样：私钥用PEM，公钥DER。DER是2进制格式，可以随便传播。私钥签发者保存，不传播。<br>
如果需要深入研究RSA(ios)，请查看我的简书系列文章：<a href='http://www.jianshu.com/p/84d925e4a57d'>揭开RSA神秘面纱


