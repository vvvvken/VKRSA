//
//  NSError+VKRSA.m
//  VKRSA
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import "NSError+VKRSA.h"



NSString *const kErrorDomainRSA = @"com.vken.RsaError";


@implementation NSError(VKRSA)


+(NSError*)rsaErrorWithDescription:(NSString*)description
{
    NSDictionary* userInfo = @{NSLocalizedDescriptionKey:description==nil?@"unknown description":description};
    NSError* error = [NSError errorWithDomain:kErrorDomainRSA code:0 userInfo:userInfo];
    
    return error;
}

+(NSError*)rsaErrorWithOSStatus:(OSStatus)status
{
    //    errSecUnimplemented                         = -4,      /* Function or operation not implemented. */
    //    errSecIO                                    = -36,     /*I/O error (bummers)*/
    //    errSecOpWr                                  = -49,     /*file already open with with write permission*/
    //    errSecParam                                 = -50,     /* One or more parameters passed to a function where not valid. */
    //    errSecAllocate                              = -108,    /* Failed to allocate memory. */
    //    errSecUserCanceled                          = -128,    /* User canceled the operation. */
    //    errSecBadReq                                = -909,    /* Bad parameter or invalid state for operation. */
    //    errSecInternalComponent                     = -2070,
    //    errSecNotAvailable                          = -25291,  /* No keychain is available. You may need to restart your computer. */
    //    errSecDuplicateItem                         = -25299,  /* The specified item already exists in the keychain. */
    //    errSecItemNotFound                          = -25300,  /* The specified item could not be found in the keychain. */
    //    errSecInteractionNotAllowed                 = -25308,  /* User interaction is not allowed. */
    //    errSecDecode                                = -26275,  /* Unable to decode the provided data. */
    //    errSecAuthFailed                            = -25293,  /* The user name or passphrase you entered is not correct. */
    
    
    if(status == errSecSuccess)
    {
        return [self rsaErrorWithDescription:@"no error"];
    }
    
    NSString* description = @"unknow error reason";
    if(status == errSecUnimplemented)
    {
        description = @"OSStatus=errSecUnimplemented,reason:Function or operation not implemented.";
    }else if(status == errSecIO)
    {
        description = @"OSStatus=errSecIO,reason:I/O error (bummers)";
    }else if(status == errSecOpWr)
    {
        description = @"OSStatus=errSecIO,reason:file already open with with write permission";
    }else if(status == errSecParam)
    {
        description = @"OSStatus=errSecIO,reason:One or more parameters passed to a function where not valid";
    }else if(status == errSecAllocate)
    {
        description = @"OSStatus=errSecIO,reason:Failed to allocate memory.";
    }else if(status == errSecUserCanceled)
    {
        description = @"OSStatus=errSecIO,reason:User canceled the operation.";
    }else if(status == errSecBadReq)
    {
        description = @"OSStatus=errSecIO,reason:Bad parameter or invalid state for operation.";
    }else if(status == errSecInternalComponent)
    {
        description = @"OSStatus=errSecIO,reason:errSecInternalComponent";
    }else if(status == errSecNotAvailable)
    {
        description = @"OSStatus=errSecIO,reason:No keychain is available. You may need to restart your computer.";
    }else if(status == errSecDuplicateItem)
    {
        description = @"OSStatus=errSecIO,reason:The specified item already exists in the keychain.";
    }else if(status == errSecItemNotFound)
    {
        description = @"OSStatus=errSecIO,reason:The specified item could not be found in the keychain.";
    }else if(status == errSecInteractionNotAllowed)
    {
        description = @"OSStatus=errSecIO,reason:User interaction is not allowed.";
    }
    else if(status == errSecDecode)
    {
        description = @"OSStatus=errSecIO,reason:Unable to decode the provided data.";
    }
    else if(status == errSecAuthFailed)
    {
        description = @"OSStatus=errSecIO,reason:The user name or passphrase you entered is not correct.";
    }
    
    return [self rsaErrorWithDescription:description];
}

@end