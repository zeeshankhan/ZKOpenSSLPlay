//
//  AppDelegate.m
//  ZKOpenSSLPlay
//
//  Created by Zeeshan Khan on 14/02/15.
//  Copyright (c) 2015 Zeeshan Khan. All rights reserved.
//

#import "AppDelegate.h"
#import "ZKEncDec.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor whiteColor];
    [self.window makeKeyAndVisible];
    [self addButton];
    return YES;
}

- (void)addButton {
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeRoundedRect];
    btn.layer.borderWidth = .8;
    btn.layer.cornerRadius = 3;
    [btn setTitle:@"Do Encryp / Decrypt" forState:UIControlStateNormal];
    btn.layer.borderColor = btn.titleLabel.textColor.CGColor;
    btn.frame = CGRectMake(10, 10, 220, 35);
    btn.center = self.window.center;
    [btn addTarget:self action:@selector(encryptDecryptAction) forControlEvents:UIControlEventTouchUpInside];
    [self.window addSubview:btn];
}

- (void)encryptDecryptAction {
    
    NSLog(@"%s",__PRETTY_FUNCTION__);
    
    ZKEncDec *edObj = [ZKEncDec new];
    
    NSArray *arrResources = @[@"EncDecTestFile.txt"];
    NSString *documentsDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    
    for (int j=0; j<arrResources.count; j++) {
        
        NSString *encKey = [NSString stringWithFormat:@"ZKKey2_%d", j];
        
        int x=0;
        for (NSString* filename in arrResources) {
            
            
            @autoreleasepool {
                
                NSArray *arrfilename = [filename componentsSeparatedByString:@"."];
                NSString *name = [arrfilename firstObject];
                NSString *ext = [arrfilename lastObject];
                
                NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:ext];
                //            NSLog(@"ENC/DEC File Path: %@", path);
                
                if (path == nil)
                    return;
                
                
                NSError *error = nil;
                NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&error];
                
                if (data != nil) {
                    
                    NSData *e = [edObj encryptChunk:data withKey:encKey];
                    NSData *d = [edObj decryptChunk:e withKey:encKey];
                    
                    if ([data isEqual:d] == NO)
                        NSLog(@"Data didn't match with key:%@", encKey);
                    
                    NSString *fileName = [NSString stringWithFormat:@"%@_%d.%@",name, j,ext];
                    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:fileName];
                    BOOL status = [d writeToFile:filePath atomically:NO];
                    if (status == FALSE)
                        NSLog(@"Document ENC/DEC Failed!!");
                    
                    x++;
                    NSLog(@"Enc Dec Done %d_%d _ %@",j+1,x, filePath);
                }
                
            }
            
        }
        
    }
    
    NSLog(@"All End Dec Done");
    
}


@end
