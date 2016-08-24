//
//  VKRSAOperator.h
//  VKRSA
//
//  Created by vkenchen on 16/8/24.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VKRSAOperator : NSObject

@property(nonatomic,assign,readonly)    SecKeyRef   privateKey;
@property(nonatomic,assign,readonly)    SecKeyRef   publicKey;

@property(nonatomic,strong,readonly)    NSError*    lastError;

+(instancetype) defaultOperator;

#pragma mark - Key
//建议使用DER格式的公钥
-(BOOL)setupPublicKeyWithDER:(NSData *)der;
//不建议使用PEM格式的公钥
-(BOOL)setupPublicKeyWithPEM:(NSString* )pem;
//为什么私钥没有DER格式？目前DER格式一般来说只用于公钥，对外传播。
-(BOOL)setupPrivateKeyWithPEM:(NSString* )pem;

#pragma mark - encrypt
- (NSData *)encryptData:(NSData *)data;
- (NSData *)encryptUTF8String:(NSString*)string;

#pragma mark - decrypt
- (NSData *)decryptData:(NSData *)data;
- (NSString* )decryptUTF8String:(NSData *)data;

#pragma mark - error
- (NSString*)lastErrorDescription;


@end
