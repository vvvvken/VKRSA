//
//  VKRSAOperator.m
//  VKRSA
//
//  Created by vkenchen on 16/8/24.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import "VKRSAOperator.h"
#import "VKRSA.h"
#import "VKRSAKey.h"
#import "NSError+VKRSA.h"

@implementation VKRSAOperator

+(instancetype) defaultOperator
{
    static dispatch_once_t once;
    static id _instance;
    dispatch_once(&once, ^{
        _instance = [[self alloc] init];
    });
    return _instance;
}

-(void)dealloc
{
    if(_privateKey != NULL)
    {
        CFRelease(_privateKey);
        _privateKey = NULL;
    }
    
    if(_publicKey != NULL)
    {
        CFRelease(_publicKey);
        _publicKey = NULL;
    }
    _lastError = nil;
}

#pragma mark - Key
-(BOOL)setupPublicKeyWithDER:(NSData *)der
{
    _lastError = nil;
    if(der == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"setupPublicKeyWithDER fail,the reason : der data is nil "];
        return NO;
    }
    
    NSError* error = nil;
    SecKeyRef key = [VKRSAKey publickeyFromDer:der ifError:&error];
    
    if(key == nil)
    {
        if(error != nil)
        {
            _lastError = error;
        }else{
            _lastError = [NSError rsaErrorWithDescription:@"setupPublicKeyWithDER fail,the reason: unknown "];
        }
        return NO;
    }
    _publicKey = key;
    return YES;
}
-(BOOL)setupPublicKeyWithPEM:(NSString* )pem
{
    _lastError = nil;
    if(pem == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"setupPublicKeyWithPEM fail,the reason : pem string is nil "];
        return NO;
    }
    
    NSError* error = nil;
    SecKeyRef key = [VKRSAKey publicKeyFromPem:pem ifError:&error];
    
    if(key == nil)
    {
        if(error != nil)
        {
            _lastError = error;
        }else{
            _lastError = [NSError rsaErrorWithDescription:@"setupPublicKeyWithPEM fail,the reason: unknown "];
        }
        return NO;
    }
    _publicKey = key;
    return YES;
}
//为什么私钥没有DER格式？目前DER格式一般来说只用于公钥，对外传播。
-(BOOL)setupPrivateKeyWithPEM:(NSString* )pem
{
    _lastError = nil;
    if(pem == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"setupPrivateKeyWithPEM fail,the reason : pem string is nil "];
        return NO;
    }
    
    NSError* error = nil;
    SecKeyRef key = [VKRSAKey privateKeyFromPem:pem ifError:&error];
    
    if(key == nil)
    {
        if(error != nil)
        {
            _lastError = error;
        }else{
            _lastError = [NSError rsaErrorWithDescription:@"setupPrivateKeyWithPEM fail,the reason: unknown "];
        }
        return NO;
    }
    
    _privateKey = key;
    return YES;
}

#pragma mark - encrypt
- (NSData *)encryptData:(NSData *)data
{
    _lastError = nil;
    if(_publicKey == NULL)
    {
        _lastError = [NSError rsaErrorWithDescription:@"encryptData fail,the reason : publick key is not ready"];
        return nil;
    }
    
    if(data == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"encryptData fail,the reason : the origin data is nil"];
        return nil;
    }
    
    NSError* error = nil;
    id result = [VKRSA encryptData:data withKey:_publicKey ifError:&error];
    if(result == nil)
    {
        if(error != nil)
        {
            _lastError = error;
        }else{
            _lastError = [NSError rsaErrorWithDescription:@"encryptData fail,the reason : VKRSA encryptData return nil"];
        }
        return nil;
    }
    
    return result;
    
}
- (NSData *)encryptUTF8String:(NSString*)string
{
    _lastError = nil;
    if(string == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"encryptUTF8String fail,the reason : the origin string is nil"];
        return nil;
    }
    
    NSData* data = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [self encryptData:data];
}


#pragma mark - decrypt
- (NSData *)decryptData:(NSData *)data
{
    _lastError = nil;
    if(_privateKey == NULL)
    {
        _lastError = [NSError rsaErrorWithDescription:@"decryptData fail,the reason:the private key is not ready "];
        return nil;
    }
    
    if(data == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"decryptData fail,the reason:the encrypted data is nil "];
        return nil;
    }
    
    NSError* error = nil;
    id result = [VKRSA decryptData:data withKey:_privateKey ifError:&error];
    if(result == nil)
    {
        if(error != nil)
        {
            _lastError = error;
        }else{
            _lastError = [NSError rsaErrorWithDescription:@"decryptData fail,the reason : VKRSA decryptData return nil"];
        }
        return nil;
    }
    
    return result;
}
- (NSString* )decryptUTF8String:(NSData *)data
{
    _lastError = nil;
    if(data == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"decryptUTF8String fail,the reason:the encrypted data is nil "];
        return nil;
    }
    
    NSData* resultData = [self decryptData: data];
    if(resultData == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"decryptUTF8String fail,the reason:the encrypted data is nil "];
        return nil;
    }
    
    NSString* resultString = [[NSString alloc]initWithData:resultData encoding:NSUTF8StringEncoding];
    if(resultString == nil)
    {
        _lastError = [NSError rsaErrorWithDescription:@"decryptUTF8String fail,the reason:the data conver to utf8 fail"];
        resultData = nil;
        return nil;
    }
    resultData = nil;
    return resultString;
}

#pragma mark - error
- (NSString*)lastErrorDescription
{
    return _lastError?_lastError.localizedDescription:@"uncaught rsa error ";
}

@end
