//
//  VKRSA.m
//  VKRSA
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import "VKRSA.h"
#import "VKRSAKey.h"
#import "NSError+VKRSA.h"

@implementation VKRSA


#pragma mark - 加密
//如果新手，不建议直接调用该方法
#pragma mark 加密实现 不建议外部直接调用该方法
+ (NSData *)encryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error
{
    /**
     OSStatus SecKeyEncrypt(
     SecKeyRef           key,
     SecPadding          padding,
     const uint8_t		*plainText,
     size_t              plainTextLen,
     uint8_t             *cipherText,
     size_t              *cipherTextLen)
     **/
    
    //第一步 准备源内容参数，参看 SecKeyEncrypt API的 3、4参数
    const uint8_t* plainText = (const uint8_t *)[data bytes];
    size_t plainTextLen = (size_t)data.length;
    
    //第二步 准备密文参数，参看 SecKeyEncrypt API的 5、6参数
    //blockSize是指 SecKeyRef 中存储的block大小
    size_t blockSize = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    uint8_t* cipherText = (uint8_t*)malloc(blockSize);  //需要用free释放，否则内存泄露
    memset(cipherText,0,blockSize);                     //初始化新分配的内存，有的编译器会自动处理，但是手动控制下是好习惯，搞C得人都懂
    
    size_t blockSizePerEncrypt = blockSize - 11;        //每次加密的block大小， -11 的原因具体不明确
    
    //第三步 准备返回的NSData
    NSMutableData* result = [NSMutableData new];
    
    //第四步 逐个block进行加密
    size_t encryptSize = 0;
    size_t needEncrpptLen = 0;
    size_t realEncryptLen = 0;
    for(encryptSize = 0; encryptSize<plainTextLen; encryptSize+=blockSizePerEncrypt )
    {
        needEncrpptLen = plainTextLen-encryptSize;
        realEncryptLen = blockSize;
        //每次加密不能超过 blockSizePerEncrypt 大小
        if(needEncrpptLen > blockSizePerEncrypt)
        {
            needEncrpptLen = blockSizePerEncrypt;
        }
        //执行加密
        OSStatus status = SecKeyEncrypt(keyRef,
                                        kSecPaddingPKCS1,
                                        plainText+encryptSize,
                                        needEncrpptLen,
                                        cipherText,
                                        &realEncryptLen);
        
        if(status == errSecSuccess)
        {
            //追加当前加密后的结果
            [result appendBytes:cipherText length:realEncryptLen];
            
        }else{
            
            *error = [NSError rsaErrorWithOSStatus:status];
            result = nil;
            break;
        }
        
        //重置临时数据
        realEncryptLen = 0;
        memset(cipherText,0,blockSize);
        
    }
    
    //释放临时内存
    free(cipherText);
    cipherText = NULL;
    
    return result;
}

#pragma mark PEM加密
+ (NSData *)encryptData:(NSData *)data withPublicPem:(NSString*)pem ifError:(NSError**)error
{
    if(data == nil)
    {
        *error = [NSError rsaErrorWithDescription:@"invalid origin data "];
        return nil;
    }
    
    SecKeyRef publicKey = [VKRSAKey publicKeyFromPem:pem ifError:error];
    if(publicKey == nil || *error)
    {
        return nil;
    }
    
    id result = [self encryptData:data withKey:publicKey ifError:error];
    
    //释放key资源
    CFRelease(publicKey);
    
    return result;
}

+ (NSData *)encryptString:(NSString*)string withPublicPem:(NSString*)pem ifError:(NSError**)error
{
    if(string == nil)
    {
        *error = [NSError rsaErrorWithDescription:@"invalid origin string "];
        return nil;
    }
    
    NSData* utfData = [string dataUsingEncoding:NSUTF8StringEncoding];
    
    return [self encryptData:utfData withPublicPem:pem ifError:error];
}

#pragma mark DER加密
+ (NSData *)encryptData:(NSData *)data withPublicDer:(NSData*)der ifError:(NSError**)error
{
    if(data == nil)
    {
        *error = [NSError rsaErrorWithDescription:@"encryptData invalid origin data "];
        return nil;
    }
    
    SecKeyRef publicKey = [VKRSAKey publickeyFromDer:der ifError:error];
    if(publicKey == nil || *error)
    {
        return nil;
    }
    
    id result = [self encryptData:data withKey:publicKey ifError:error];
    
    //释放key资源
    CFRelease(publicKey);
    
    return result;
    
    
}
+ (NSData *)encryptString:(NSString*)string withPublicDer:(NSData*)der ifError:(NSError**)error
{
    if(string == nil)
    {
        *error = [NSError rsaErrorWithDescription:@"encryptString invalid origin string "];
        return nil;
    }
    
    NSData* utfData = [string dataUsingEncoding:NSUTF8StringEncoding];
    
    return [self encryptData:utfData withPublicDer:der ifError:error];
}

#pragma mark - 解密
#pragma mark 解密实现 不建议外部直接调用该方法
+ (NSData *)decryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error
{
    //    OSStatus SecKeyDecrypt(
    //                           SecKeyRef           key,                /* Private key */
    //                           SecPadding          padding,			/* kSecPaddingNone,
    //                                                                 kSecPaddingPKCS1,
    //                                                                 kSecPaddingOAEP */
    //                           const uint8_t       *cipherText,
    //                           size_t              cipherTextLen,		/* length of cipherText */
    //                           uint8_t             *plainText,
    //                           size_t              *plainTextLen)		/* IN/OUT */
    
    //第一步 准备源内容参数，参看 SecKeyDecrypt API的 3、4参数
    const uint8_t* cipherText = (const uint8_t *)[data bytes];
    size_t cipherTextLen = (size_t)data.length;
    
    //第二步 准备密文参数，参看 SecKeyDecrypt API的 5、6参数
    //blockSize是指 SecKeyRef 中存储的block大小
    size_t blockSize = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    uint8_t* plainText = (uint8_t*)malloc(blockSize);   //需要用free释放，否则内存泄露
    memset(plainText,0,blockSize);                      //初始化新分配的内存，有的编译器会自动处理，但是手动控制下是好习惯，搞C得人都懂
    size_t blockSizePerDecrypt = blockSize;             //每次解密的block大小
    
    //第三步 准备返回的NSData
    NSMutableData* result = [NSMutableData new];
    
    //第四步 逐个block进行加密
    size_t decryptSize = 0;
    size_t needDecrpptLen = 0;
    size_t realDecryptLen = 0;
    for(decryptSize = 0;decryptSize<cipherTextLen;decryptSize+=blockSizePerDecrypt)
    {
        
        needDecrpptLen = cipherTextLen-decryptSize;
        realDecryptLen = blockSize;
        if(needDecrpptLen > blockSizePerDecrypt)
        {
            needDecrpptLen = blockSizePerDecrypt;
        }
        OSStatus status= SecKeyDecrypt(keyRef,
                                       kSecPaddingPKCS1,
                                       cipherText + decryptSize,
                                       needDecrpptLen,
                                       plainText,
                                       &realDecryptLen
                                       );
        if(status == errSecSuccess)
        {
            //定位实际的内容 0data0
            int dataStart = -1;
            int dataEnd = (int)realDecryptLen;
            for ( int i = 0; i < realDecryptLen; i++ ) {
                //第一个0，表示dataStart;
                //第二个0，表示dataEnd
                if ( plainText[i] == 0 ) {
                    if ( dataStart < 0 ) {
                        dataStart = i;
                    } else {
                        dataEnd = i;
                        break;
                    }
                }
            }
            //安全保护，实际这句不会执行
            if(dataStart==-1)
                dataStart = 0;
            //追加当前加密后的结果
            [result appendBytes:plainText+dataStart length:dataEnd-dataStart];
            
        }else{
            *error = [NSError rsaErrorWithOSStatus:status];
            result = nil;
            break;
        }
        
        //重置临时数据
        realDecryptLen = 0;
        memset(plainText,0,blockSize);
    }
    
    free(plainText);
    plainText = NULL;
    
    return result;
}

#pragma mark PEM解密
+ (NSData *)decryptData:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error
{
    if(data == nil)
    {
        *error = [NSError rsaErrorWithDescription:@"decryptData invalid encrypt data "];
        return nil;
    }
    
    SecKeyRef privateKey = [VKRSAKey privateKeyFromPem:pem ifError:error];
    if(privateKey == nil || *error)
    {
        return nil;
    }
    
    id result = [self decryptData:data withKey:privateKey ifError:error];
    
    //释放key资源
    CFRelease(privateKey);
    
    return result;
}
+ (NSString* )decryptString:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error
{
    NSData* result = [self decryptData:data withPrivatePem:pem ifError:error];
    if(*error)
    {
        return nil;
    }
    
    NSString* resultString = [[NSString alloc]initWithData:result encoding:NSUTF8StringEncoding];
    return resultString;
}

@end
