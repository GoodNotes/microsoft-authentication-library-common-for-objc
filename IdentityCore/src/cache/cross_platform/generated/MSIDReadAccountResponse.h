// AUTOGENERATED FILE - DO NOT MODIFY!
// This file generated by Djinni from cache.djinni

#import "MSIDAccount.h"
#import "MSIDOperationStatus.h"
#import <Foundation/Foundation.h>

@interface MSIDReadAccountResponse : NSObject
- (nonnull instancetype)initWithAccount:(nonnull MSIDAccount *)account
                                 status:(nonnull MSIDOperationStatus *)status;
+ (nonnull instancetype)readAccountResponseWithAccount:(nonnull MSIDAccount *)account
                                                status:(nonnull MSIDOperationStatus *)status;

@property (nonatomic, readonly, nonnull) MSIDAccount * account;

@property (nonatomic, readonly, nonnull) MSIDOperationStatus * status;

@end