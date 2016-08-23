//
//  NSError+VKRSA.h
//  VKRSA
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSError(VKRSA)

+(NSError*)rsaErrorWithDescription:(NSString*)description;

+(NSError*)rsaErrorWithOSStatus:(OSStatus)status;

@end
