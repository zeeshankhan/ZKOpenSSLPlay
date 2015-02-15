//
//  ZKEncDec.h
//  ZKEncDec
//
//  Created by Zeeshan Khan on 03/07/13.
//  Copyright (c) 2013 Zeeshan. All rights reserved.
//

#import <Foundation/Foundation.h>

//unsigned char *encryptData(unsigned char *key_data, char *data, int *len) ;
//char *decryptData(unsigned char *key_data, unsigned char *ciphertext, int *clen);

@interface ZKEncDec : NSObject

- (NSData*)encryptChunk:(NSData*)data withKey:(NSString*)key;
- (NSData*)decryptChunk:(NSData*)data withKey:(NSString*)key;

@end