//The MIT License (MIT)
//
//Copyright (c) 2014 sothic
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.


#import "SLUtility.h"
#import "Base64.h"
#import "NSData+Base64.h"
#import "NSString+Base64.h"
#import "NSData+CommonCrypto.h"

@implementation SLUtility

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
    NSData *dataSalt = [SLUtility randomDataOfLength:8];
    return dataSalt;
}

+ (NSData *)generateIV128
{
    NSData *dataIV = [SLUtility randomDataOfLength:16];
    return dataIV;
}

+ (NSData *)generate192Key:(const void *)fixedKey keyLength:(NSUInteger)length salt:(NSData *)salt
{
    NSMutableData *keyData = [NSMutableData dataWithBytes:fixedKey length:length];
    [keyData appendData:salt];
    return keyData;
}

@end
