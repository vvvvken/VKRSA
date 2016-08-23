//
//  VKRSA.h
//  VKRSA_iOSDemo
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VKRSA : NSObject


#pragma mark - 加密
//如果新手，不建议直接调用该方法
#pragma mark 加密实现 不建议外部直接调用该方法
+ (NSData *)encryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error;

#pragma mark PEM加密
+ (NSData *)encryptData:(NSData *)data withPublicPem:(NSString*)pem ifError:(NSError**)error;
+ (NSData *)encryptString:(NSString*)string withPublicPem:(NSString*)pem ifError:(NSError**)error;

#pragma mark DER加密
+ (NSData *)encryptData:(NSData *)data withPublicDer:(NSData*)der ifError:(NSError**)error;
+ (NSData *)encryptString:(NSString*)string withPublicDer:(NSData*)der ifError:(NSError**)error;

#pragma mark - 解密
#pragma mark 解密实现 不建议外部直接调用该方法
+ (NSData *)decryptData:(NSData *)data withKey:(SecKeyRef)keyRef ifError:(NSError**)error;

#pragma mark PEM解密
+ (NSData *)decryptData:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error;
+ (NSString* )decryptString:(NSData *)data withPrivatePem:(NSString*)pem ifError:(NSError**)error;



@end
