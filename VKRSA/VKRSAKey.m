//
//  VKRSAKey.m
//  VKRSA
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import "VKRSAKey.h"
#import "NSError+VKRSA.h"

@implementation VKRSAKey

static NSData *base64_decode(NSString *str){
    //    它们将“+/”改为“_-”
    str = [str stringByReplacingOccurrencesOfString:@"-" withString:@"/"];
    str = [str stringByReplacingOccurrencesOfString:@"_" withString:@"+"];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

#pragma mark - PEM格式
+ (SecKeyRef)privateKeyFromPem:(NSString *)privateKey ifError:(NSError **)error
{
    //PEM格式String转SecKeyRef
    //核心思想是把证书安装到keychain，得到SecKeyRef对象
    //1.把PEM格式中的KeyData提取出来
    //2.把data添加到keychain中，得到SecKeyRef
    
    NSData* keyData = [self dataTrimFromPrivatePem:privateKey];
    if(keyData!=nil)
    {
        return [self privateKeyFromData:keyData andTag:@"vkrsa.privatekey" error:error];
    }else{
        *error = [NSError rsaErrorWithDescription:@"pem data is invalid private pem data"];
        return nil;
    }
}
+ (SecKeyRef)publicKeyFromPem:(NSString *)publicKey ifError:(NSError **)error
{
    //PEM格式String转SecKeyRef
    //核心思想是把证书安装到keychain，得到SecKeyRef对象
    //1.把PEM格式中的KeyData提取出来
    //2.把data添加到keychain中，得到SecKeyRef
    
    NSData* keyData = [self dataTrimFromPublicPem:publicKey];
    if(keyData!=nil)
    {
        return [self publicKeyFromData:keyData andTag:@"vkrsa.publickey" error:error];
    }else{
        //todo error handle
        *error = [NSError rsaErrorWithDescription:@"pem data is invalid public pem data"];
        return nil;
    }
}

#pragma makr - DER格式
+ (SecKeyRef)publickeyFromDer:(NSData*)data ifError:(NSError **)error
{
    if(data == nil)
    {
        *error = [NSError rsaErrorWithDescription:@"der data is nil"];
        return nil;
    }
    
    //创建证书对象
    SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, ( __bridge CFDataRef)data);
    if (certificate == nil) {
        *error = [NSError rsaErrorWithDescription:@"Can not read certificate"];
        return nil;
    }
    
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust;
    OSStatus trustStatus = SecTrustCreateWithCertificates(certificate, policy, &trust);
    if (trustStatus != errSecSuccess) {
        *error = [NSError rsaErrorWithOSStatus:trustStatus];
        return nil;
    }
    
    SecTrustResultType trustResultType;
    trustStatus = SecTrustEvaluate(trust, &trustResultType);
    if (trustStatus != errSecSuccess) {
        *error = [NSError rsaErrorWithOSStatus:trustStatus];
        return nil;
    }
    
    SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
    if (publicKey == nil) {
        *error = [NSError rsaErrorWithDescription:@"SecTrustCopyPublicKey fail"];
        return nil;
    }
    
    return publicKey;
}

#pragma mark - SecKeyRef生成

+( SecKeyRef)privateKeyFromData:(NSData*)data andTag:(NSString*)tag error:(NSError **)error
{
    NSData *tagData = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    //删除KeyChainItem，必须指定两项 kSecAttrApplicationTag 和 kSecClass
    NSMutableDictionary* deleteDic = [NSMutableDictionary new];
    [deleteDic setObject:tagData forKey:(__bridge id)kSecAttrApplicationTag];
    [deleteDic setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)deleteDic);
    
    //添加KeyChainItem
    NSMutableDictionary *addDic = [[NSMutableDictionary alloc] init];
    //密钥数据
    [addDic setObject:data forKey:(__bridge id)kSecValueData];
    //key chain item tag
    [addDic setObject:tagData forKey:(__bridge id)kSecAttrApplicationTag];
    [addDic setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    //密钥种类为RSA密钥
    [addDic setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    //密钥类型不需要指定，亲测，公钥和私钥都可以用
    //[addDic setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id) kSecAttrKeyClass];
    [addDic setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id) kSecAttrKeyClass];
    
    [addDic setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    
    SecKeyRef keyRef = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addDic, (CFTypeRef *)&keyRef);
    if(status == errSecSuccess)
    {
        return keyRef;
    }else{
        *error = [NSError rsaErrorWithOSStatus:status];
        return nil;
    }
}

+( SecKeyRef)publicKeyFromData:(NSData*)data andTag:(NSString*)tag error:(NSError **)error
{
    NSData *tagData = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    //删除KeyChainItem，必须指定两项 kSecAttrApplicationTag 和 kSecClass
    NSMutableDictionary* deleteDic = [NSMutableDictionary new];
    [deleteDic setObject:tagData forKey:(__bridge id)kSecAttrApplicationTag];
    [deleteDic setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)deleteDic);
    
    //添加KeyChainItem
    NSMutableDictionary *addDic = [[NSMutableDictionary alloc] init];
    //密钥数据
    [addDic setObject:data forKey:(__bridge id)kSecValueData];
    //key chain item tag
    [addDic setObject:tagData forKey:(__bridge id)kSecAttrApplicationTag];
    [addDic setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    //密钥种类为RSA密钥
    [addDic setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    //密钥类型不需要指定，亲测，公钥和私钥都可以用
    [addDic setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id) kSecAttrKeyClass];
    //[addDic setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id) kSecAttrKeyClass];
    
    [addDic setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    
    SecKeyRef keyRef = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addDic, (CFTypeRef *)&keyRef);
    if(status == errSecSuccess)
    {
        return keyRef;
    }else{
        *error = [NSError rsaErrorWithOSStatus:status];
        return nil;
    }
}

#pragma mark - RSAHeader 数据处理

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx	 = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key{
    // Skip ASN.1 private key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx	 = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    // Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

+ (NSData*) dataTrimFromPublicPem:(NSString*)key
{
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = base64_decode(key);
    data = [self stripPublicKeyHeader:data];
    if(!data){
        return nil;
    }
    return data;
}



+ (NSData*) dataTrimFromPrivatePem:(NSString*)key
{
    NSRange spos = [key rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PRIVATE KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = base64_decode(key);
    data = [self stripPrivateKeyHeader:data];
    if(!data){
        return nil;
    }
    return data;
}

@end