//
//  ZKEncDec.m
//  ZKEncDec
//
//  Created by Zeeshan Khan on 03/07/13.
//  Copyright (c) 2013 Zeeshan. All rights reserved.
//

/**
 AES encryption/decryption demo program using OpenSSL EVP apis
 gcc -Wall openssl_aes.c -lcrypto
 **/

#import "ZKEncDec.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#pragma mark - Private Functions

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
             EVP_CIPHER_CTX *d_ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
    
    /*
     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32) {
        NSLog(@"Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }
    
    EVP_CIPHER_CTX_init(e_ctx);
    if (EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv) == 0) {
        return -1;
    }
    
    EVP_CIPHER_CTX_init(d_ctx);
    if (EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv) == 0) {
        return -1;
    }
    
    return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char *)malloc(c_len);
    
    /* allows reusing of 'e' for multiple encryption cycles */
    if(!EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL)) {
        free(ciphertext);
        NSLog(@"ERROR in EVP_EncryptInit_ex \n");
        return NULL;
    }
    
    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     *len is the size of plaintext in bytes */
    if(!EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len)){
        free(ciphertext);
        NSLog(@"ERROR in EVP_EncryptUpdate \n");
        return NULL;
    }
    
    /* update ciphertext with the final remaining bytes */
    if(!EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len)){ //
        free(ciphertext);
        NSLog(@"ERROR in EVP_EncryptFinal_ex \n");
        return NULL;
    }
   
    *len = c_len + f_len;
    //printf("\n1. %zd\n", strlen((char*)ciphertext));
    //ciphertext[*len] = '\0';
    //printf("\n2. %zd\n", strlen((char*)ciphertext));
    
    return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = (unsigned char *)malloc(p_len+AES_BLOCK_SIZE);
    
    if(!EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL)){
        free(plaintext);
        NSLog(@"ERROR in EVP_DecryptInit_ex \n");
        return NULL;
    }
    
    if(!EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len)){
        free(plaintext);
        NSLog(@"ERROR in EVP_DecryptUpdate\n");
        return NULL;
    }
    
    if(!EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len)){
        free(plaintext);
        NSLog(@"ERROR in EVP_DecryptFinal_ex\n");
        return NULL;
    }
    
    *len = p_len + f_len;
    return plaintext;
}

#pragma mark - User functions

unsigned char *encryptData(unsigned char *key_data, char *data, int *len) {
    
    EVP_CIPHER_CTX en, de;
    
    unsigned char salt[] = {1,2,3,4,5,6,7,8};
    
    int key_data_len;
    key_data_len = strlen((char*)key_data);
    
    if (aes_init(key_data, key_data_len, salt, &en, &de)) {
        NSLog(@"Couldn't initialize AES cipher\n");
        return NULL;
    }
    
    //*len = strlen(data)+1;
    unsigned char* cipherdata = NULL;
    cipherdata = aes_encrypt(&en, (unsigned char *)data, len);
    EVP_CIPHER_CTX_cleanup(&en);
    EVP_CIPHER_CTX_cleanup(&de);
    return cipherdata;
    
}

char *decryptData(unsigned char *key_data, unsigned char *ciphertext, int *clen) {
    EVP_CIPHER_CTX en, de;
    
    unsigned char salt[] = {1,2,3,4,5,6,7,8};
    
    int key_data_len;
    key_data_len = strlen((char*)key_data);
    
    if (aes_init(key_data, key_data_len, salt, &en, &de)) {
        NSLog(@"Couldn't initialize AES cipher\n");
        return NULL;
    }
    
    char *plaintext = NULL;
    plaintext = (char *)aes_decrypt(&de, ciphertext, clen);
    EVP_CIPHER_CTX_cleanup(&en);
    EVP_CIPHER_CTX_cleanup(&de);
    return plaintext;
    
}

#pragma mark - Objective C Functions

#define SYM_KEY_SZ 16

@implementation ZKEncDec

- (NSData*)encryptChunk:(NSData*)data withKey:(NSString*)key {
    NSMutableData *cData = [NSMutableData new];
    @autoreleasepool {
        unsigned char* key_data = (unsigned char*)[key UTF8String];
        unsigned char *ciphertext = NULL;
        int len = [data length];
        ciphertext = encryptData(key_data, (char*)[data bytes], &len);
        //    NSAssert(ciphertext != NULL, @"Encrypted char is NULL");
        if (ciphertext != NULL) {
            [cData appendBytes:ciphertext length:len];
            data = nil;
            key = nil;
            RAND_bytes(ciphertext, SYM_KEY_SZ);
            free(ciphertext);
        }
        data = nil;
        key = nil;
    }
    return [cData autorelease]; //[NSData dataWithData:[cData autorelease]];
}

- (NSData*)decryptChunk:(NSData*)data withKey:(NSString*)key {
    NSMutableData *pData = [NSMutableData new];
    @autoreleasepool {
        unsigned char* key_data = (unsigned char*)[key UTF8String];
        char *plaintext = NULL;
        int len = [data length];
        plaintext = decryptData(key_data, (unsigned char*)[data bytes], &len);
        //    NSAssert(plaintext != NULL, @"Decrypted char is NULL");
        if (plaintext != NULL) {
            [pData appendBytes:plaintext length:len];
            RAND_bytes(plaintext, SYM_KEY_SZ);
            free(plaintext);
        }
        data = nil;
        key = nil;
    }
    return [pData autorelease];//[NSData dataWithData:[pData autorelease]];
}


@end


