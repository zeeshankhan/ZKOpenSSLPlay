//
//  ZKEncDec.h
//  ZKEncDec
//
//  Created by Zeeshan Khan on 14/02/15.
//  Copyright (c) 2015 Zeeshan. All rights reserved.
//

#import <Foundation/Foundation.h>

//unsigned char *encryptData(unsigned char *key_data, char *data, int *len) ;
//char *decryptData(unsigned char *key_data, unsigned char *ciphertext, int *clen);

@interface ZKEncDec : NSObject

- (NSData*)encryptChunk:(NSData*)data withKey:(NSString*)key;
- (NSData*)decryptChunk:(NSData*)data withKey:(NSString*)key;

@end