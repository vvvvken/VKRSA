//
//  ViewController.m
//  VKRSA_iOSDemo
//
//  Created by vkenchen on 16/8/23.
//  Copyright © 2016年 Vkenchen. All rights reserved.
//

#import "ViewController.h"

#import "VKRSA.h"
#import "VKRSAOperator.h"



@interface ViewController ()

@property(nonatomic,copy) NSString*   privateKeyPem;
@property(nonatomic,copy) NSString*   publicKeyPem;
@property(nonatomic,copy) NSData*     publicKeyDer;

@property(nonatomic,copy) NSString*     testString;
@property(nonatomic,retain) NSData*     testData;


@property(nonatomic,retain) NSData*     testStringEncryptResult;
@property(nonatomic,retain) NSData*     testDataEncryptResult;

@property(nonatomic,retain) NSData*     testStringEncryptResultFromRSAOperator;
@property(nonatomic,retain) NSData*     testDataEncryptResultFromRSAOperator;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSError* error = nil;
    
    NSString* file = [[NSBundle mainBundle]pathForResource:@"rsa_private_key_pkcs8" ofType:@"pem"];
    self.privateKeyPem = [NSString stringWithContentsOfFile:file encoding:NSUTF8StringEncoding error:&error];
    
    file = [[NSBundle mainBundle]pathForResource:@"rsa_public_key" ofType:@"pem"];
    self.publicKeyPem = [NSString stringWithContentsOfFile:file encoding:NSUTF8StringEncoding error:&error];
    
    file = [[NSBundle mainBundle]pathForResource:@"rsa_public_key" ofType:@"der"];
    self.publicKeyDer = [NSData dataWithContentsOfFile:file];
    
    
    self.testString = @"this is rsa, it's the best rsa library of ios";
    
    //用AppDelegate.m文件来做测试Data
    file = [[NSBundle mainBundle]pathForResource:@"keystore" ofType:@"jwks"];
    _testData = [NSData dataWithContentsOfFile:file];
    
    
    [self setupRSAOperator];
    
}

-(void)setupRSAOperator
{
    clock_t tickStart = clock();
    BOOL privateReady =  [[VKRSAOperator defaultOperator]setupPrivateKeyWithPEM:self.privateKeyPem];
    clock_t time = clock() - tickStart;
    if(privateReady)
    {
        NSLog(@"VKRSAOperator PEM 私钥创建成功,用时：%lu 毫秒",time);
    }else{
        NSLog(@"VKRSAOperator PEM 私钥创建失败，原因：%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
    }
    
    
    tickStart = clock();
    BOOL publickReady = [[VKRSAOperator defaultOperator]setupPublicKeyWithDER:self.publicKeyDer];
    time = clock() - tickStart;
    if(publickReady)
    {
        NSLog(@"VKRSAOperator DER 公钥创建成功,用时：%lu 毫秒",time);
    }else{
        NSLog(@"VKRSAOperator DER 公钥创建失败，原因：%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
    }
    
    
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
#pragma mark - NSString验证

- (IBAction)onEncryptStringWithPEM:(id)sender {
    
    NSError *error = nil;
    
    clock_t tickStart = clock();
    self.testStringEncryptResult = [VKRSA encryptString:self.testString withPublicPem:self.publicKeyPem ifError:&error];
    clock_t time = clock() - tickStart;
    
    if(error)
    {
        NSLog(@"VKRSA NSString PEM 加密错误:%@", error.localizedDescription );
    }else{
        NSLog(@"VKRSA NSString PEM 加密成功，用时：%lu 毫秒",time);
    }
    
}
- (IBAction)onEncryptStringWithDER:(id)sender {
    
    NSError *error = nil;
    
    clock_t tickStart = clock();
    self.testStringEncryptResult = [VKRSA encryptString:self.testString withPublicDer:self.publicKeyDer ifError:&error];
    clock_t time = clock() - tickStart;
    
    if(error)
    {
        NSLog(@"VKRSA NSString DER 加密错误:%@", error.localizedDescription );
    }else{
        NSLog(@"VKRSA NSString DER 加密成功，用时：%lu 毫秒",time);
    }
    
    
    tickStart = clock();
    self.testStringEncryptResultFromRSAOperator = [[VKRSAOperator defaultOperator]encryptUTF8String:self.testString];
    clock_t timeOperator = clock() - tickStart;
    if(self.testStringEncryptResultFromRSAOperator == nil)
    {
        NSLog(@"VKRSAOperator NSString DER 加密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
    }else{
        NSLog(@"VKRSAOperator NSString DER 加密成功，用时：%lu 毫秒",timeOperator);
    }
    
}
- (IBAction)onDecryptStringWithPEM:(id)sender {
    
    
    NSError *error = nil;
    
    clock_t tickStart = clock();
    
    NSString* result = [VKRSA decryptString:self.testStringEncryptResult withPrivatePem:self.privateKeyPem ifError:&error];
    
    clock_t time = clock() - tickStart;
    if(error)
    {
        NSLog(@"VKRSA NSString PEM 解密错误:%@", error.localizedDescription );
    }else{
        NSLog(@"VKRSA NSString PEM 解密成功，用时：%lu 毫秒，\r结果为：%@",time,result);
    }
    
    tickStart = clock();
    NSString* resultFromRSAOperator = [[VKRSAOperator defaultOperator]decryptUTF8String:self.testStringEncryptResultFromRSAOperator];
    clock_t timeOperator = clock() - tickStart;
    if(resultFromRSAOperator == nil)
    {
        NSLog(@"VKRSAOperator NSString DER 解密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
    }else{
        NSLog(@"VKRSAOperator NSString DER 解密成功，用时：%lu 毫秒，\r结果为：%@",timeOperator,resultFromRSAOperator);
    }
    
}

#pragma mark - NSData验证
- (IBAction)onEncryptDataWithPEM:(id)sender {
    
    NSError *error = nil;
    
    clock_t tickStart = clock();
    self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicPem:self.publicKeyPem ifError:&error];
    clock_t time = clock() - tickStart;
    
    if(error)
    {
        NSLog(@"VKRSA NSData PEM 加密错误:%@", error.localizedDescription );
    }else{
        NSLog(@"VKRSA NSData PEM 加密成功，用时：%lu 毫秒",time);
    }
    
}
- (IBAction)onEncryptDataWithDER:(id)sender {
  
    NSError *error = nil;
    
    clock_t tickStart = clock();
    self.testDataEncryptResult = [VKRSA encryptData:self.testData withPublicDer:self.publicKeyDer ifError:&error];
    clock_t time = clock() - tickStart;
    
    if(error)
    {
        NSLog(@"VKRSA NSData DER 加密错误:%@", error.localizedDescription );
    }else{
        NSLog(@"VKRSA NSData DER  加密成功，用时：%lu 毫秒",time);
    }
    
    
    tickStart = clock();
    self.testDataEncryptResultFromRSAOperator = [[VKRSAOperator defaultOperator]encryptData:self.testData];
    clock_t timeOperator = clock() - tickStart;
    if(self.testDataEncryptResultFromRSAOperator == nil)
    {
        NSLog(@"VKRSAOperator NSData DER 加密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
    }else{
        NSLog(@"VKRSAOperator NSData DER 加密成功，用时：%lu 毫秒",timeOperator);
    }
    
}
- (IBAction)onDecryptDataWithPEM:(id)sender {
    
    
    NSError *error = nil;
    
    clock_t tickStart = clock();
    
    NSData* result = [VKRSA decryptData:self.testDataEncryptResult withPrivatePem:self.privateKeyPem ifError:&error];
    
    clock_t time = clock() - tickStart;
    
    if(error)
    {
        NSLog(@"VKRSA NSData PEM 解密错误:%@", error.localizedDescription );
    }else{
        
        NSString* resultString = [[NSString alloc]initWithData:result encoding:NSUTF8StringEncoding];
        
        NSLog(@"VKRSA NSData PEM 解密成功，用时：%lu 毫秒，\r结果为：%@",time,resultString);
    }
    
    
    tickStart = clock();
    NSData* resultOperator = [[VKRSAOperator defaultOperator]decryptData:self.testDataEncryptResultFromRSAOperator];
    clock_t timeOperator = clock() - tickStart;
    if(self.testDataEncryptResultFromRSAOperator == nil)
    {
        NSLog(@"VKRSAOperator NSData DER 加密错误:%@",[[VKRSAOperator defaultOperator] lastErrorDescription]);
    }else{
        NSString* resultString = [[NSString alloc]initWithData:resultOperator encoding:NSUTF8StringEncoding];
        NSLog(@"VKRSAOperator NSData DER 加密成功，用时：%lu 毫秒,\r结果为：%@",timeOperator,resultString);
    }
    
}

@end
