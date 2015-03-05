//
//  AESCrypt.m
//  Gurpartap Singh
//
//  Created by Gurpartap Singh on 06/05/12.
//  Copyright (c) 2012 Gurpartap Singh
// 
// 	MIT License
// 
// 	Permission is hereby granted, free of charge, to any person obtaining
// 	a copy of this software and associated documentation files (the
// 	"Software"), to deal in the Software without restriction, including
// 	without limitation the rights to use, copy, modify, merge, publish,
// 	distribute, sublicense, and/or sell copies of the Software, and to
// 	permit persons to whom the Software is furnished to do so, subject to
// 	the following conditions:
// 
// 	The above copyright notice and this permission notice shall be
// 	included in all copies or substantial portions of the Software.
// 
// 	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// 	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// 	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// 	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// 	LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// 	OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// 	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import "AESCrypt.h"

#import "NSData+Base64.h"
#import "NSString+Base64.h"
#import "NSData+CommonCrypto.h"


#define KEYBITS 128

@implementation AESCrypt

+ (NSString *)encrypt:(NSString *)message password:(NSString *)password {
  NSData *encryptedData = [[message dataUsingEncoding:NSUTF8StringEncoding] AES256EncryptedDataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
  NSString *base64EncodedString = [NSString base64StringFromData:encryptedData length:[encryptedData length]];
  return base64EncodedString;
}

+ (NSString *)decrypt:(NSString *)base64EncodedString password:(NSString *)password {
  NSData *encryptedData = [NSData base64DataFromString:base64EncodedString];
  NSData *decryptedData = [encryptedData decryptedAES256DataUsingKey:[[password dataUsingEncoding:NSUTF8StringEncoding] SHA256Hash] error:nil];
  return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

/*for 128 fixed + 64 salt and 128 initial vendor*/

+ (NSString *)encrypt:(NSString *)message password:(NSData *)password iv:(NSData *)iv {
    NSData *encryptedData = [[message dataUsingEncoding:NSUTF8StringEncoding] dataEncryptedUsingAlgorithm:kCCAlgorithmAES128 key:password initializationVector:iv options:kCCOptionPKCS7Padding error:nil];
    NSString *base64EncodedString = [NSString base64StringFromData:encryptedData length:[encryptedData length]];
    return base64EncodedString;
}

+ (NSString *)decrypt:(NSString *)base64EncodedString password:(NSData *)password iv:(NSData *) iv{
    NSData *encryptedData = [NSData base64DataFromString:base64EncodedString];
    NSData *decryptedData = [encryptedData decryptedDataUsingAlgorithm:kCCAlgorithmAES128 key:password  initializationVector: iv  options:kCCOptionPKCS7Padding  error:nil];
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}


+ (NSData *)randomDataOfLength:(size_t)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result;
    if (SecRandomCopyBytes != NULL) {
        result = SecRandomCopyBytes(NULL, length, data.mutableBytes);
    }

    NSAssert(result == 0, @"Unable to generate random bytes: %d", errno);
    
    return data;
}


+ (NSData *)generateSalt64
{
//    unsigned char salt[8];
//    for (int i = 0; i < 8; i++) {
//        salt[i] = (unsigned char)arc4random();
//    }
//
//    NSData *dataSalt = [NSData dataWithBytes:salt length:sizeof(salt)];
  
    
    NSData *dataSalt = [AESCrypt randomDataOfLength:8];
    
    return dataSalt;
}

+ (NSData *)generateIV128
{
//    unsigned char iv[16];
//    for (int i = 0; i < 16; i++) {
//        iv[i] = (unsigned char)arc4random();
//    }

//    unsigned char iv[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
//    NSData *dataIV = [NSData dataWithBytes:iv length:sizeof(iv)];

    
    NSData *dataIV = [AESCrypt randomDataOfLength:16];

    return dataIV;
}

+ (NSData *)generate192Key:(unsigned char *)fixedKey salt:(NSData *)salt
{
    
    
   // unsigned char fixedKey [16]= { 0x56, 0x5F, 0x34, 0x97, 0x68, 0x5B, 0xD6, 0xA1, 0x5A, 0x72, 0x5C, 0xA0, 0x32, 0x56, 0x38, 0x0D };

   // unsigned char key[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
    
    NSMutableData *keyData = [NSMutableData dataWithBytes:fixedKey length:sizeof(fixedKey)];
    
    [keyData appendData:salt];
    
    return keyData;
}


@end
