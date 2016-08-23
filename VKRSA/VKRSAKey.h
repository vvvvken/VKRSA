//
//  VKRSAKey.h
//  VKRSA_iOSDemo
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VKRSAKey : NSObject

#pragma mark - PEM格式
+ (SecKeyRef)privateKeyFromPem:(NSString *)privateKey ifError:(NSError **)error;
+ (SecKeyRef)publicKeyFromPem:(NSString *)publicKey ifError:(NSError **)error;

#pragma makr - DER格式
+ (SecKeyRef)publickeyFromDer:(NSData*)data ifError:(NSError **)error;


@end
