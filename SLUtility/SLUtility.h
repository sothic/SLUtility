//
//  SLUtility.h
//  SLUtility
//
//  Created by Sothic Lee on 6/3/14.
//  Copyright (c) 2014 sothic. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SLUtility : NSObject

+ (NSString *)encrypt:(NSString *)message password:(NSData *)password iv:(NSData *)iv;
+ (NSString *)decrypt:(NSString *)base64EncodedString password:(NSData *)password iv:(NSData *) iv;
+ (NSData *)generateSalt64;
+ (NSData *)generateIV128;
+ (NSData *)generate192Key:(const void *)fixedKey keyLength:(NSUInteger)length salt:(NSData *)salt;

@end
