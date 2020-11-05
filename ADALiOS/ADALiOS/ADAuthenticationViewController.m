// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADAuthenticationDelegate.h"
#import "ADAuthenticationWebViewController.h"
#import "ADAuthenticationViewController.h"
#import "ADLogger.h"

@interface ADAuthenticationViewController ( ) <ADAuthenticationDelegate, WKNavigationDelegate>
@end

@implementation ADAuthenticationViewController
{
    ADAuthenticationWebViewController *_webAuthenticationWebViewController;

    BOOL      _loading;
}

#pragma mark - UIViewController Methods

- (void)viewDidLoad
{
    [super viewDidLoad];

    _loading   = NO;
    
    if ( (NSUInteger)[[[UIDevice currentDevice] systemVersion] doubleValue] < 7)
    {
        [self.navigationController.navigationBar setTintColor:[UIColor darkGrayColor]];
    }
}

- (void)viewDidUnload
{
    DebugLog();
    
    [super viewDidUnload];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    if ( UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad )
        // The device is an iPad running iPhone 3.2 or later.
        return YES;
    else
        return (interfaceOrientation == UIInterfaceOrientationPortrait);
}

#pragma mark - Event Handlers

// Authentication was cancelled by the user
- (IBAction)onCancel:(id)sender
{
#pragma unused(sender)
    
    [self webAuthenticationDidCancel];
}

// Fired 2 seconds after a page loads starts to show waiting indicator
- (void)onStartActivityIndicator:(id)sender
{
#pragma unused(sender)
    
    if ( _loading )
        [_activityIndicator startAnimating];
}

// Launches the UIWebView with a start URL. The UIWebView is halted when a
// prefix of the end URL is reached.
- (BOOL)startWithURL:(NSURL *)startURL endAtURL:(NSURL *)endURL
{
    _webAuthenticationWebViewController = [[ADAuthenticationWebViewController alloc] initWithWebView:_webView startAtURL:startURL endAtURL:endURL];
    
    if ( _webAuthenticationWebViewController )
    {
        // Delegate set up: this object is the delegate for the ADAuthenticationWebViewController,
        // and the controller will have established itself as the delegate for the UIWebView. However,
        // this object also wants events from the UIWebView to control the activity indicator so we
        // hijack the delegate here and forward events as they are seen in this object.
        _webAuthenticationWebViewController.delegate = self;
        _webView.navigationDelegate                  = self;
        
        [_webAuthenticationWebViewController start];
        return YES;
    }
    else
    {
        return NO;
    }
}

#pragma mark - ADAuthenticationDelegate

- (void)webAuthenticationDidCancel
{
    [_webAuthenticationWebViewController stop];
    NSAssert( nil != _delegate, @"Delegate object was lost" );
    [_delegate webAuthenticationDidCancel];
}

- (void)webAuthenticationDidCompleteWithURL:(NSURL *)endURL
{
    [_webAuthenticationWebViewController stop];
    NSAssert( nil != _delegate, @"Delegate object was lost" );
    [_delegate webAuthenticationDidCompleteWithURL:endURL];
}

- (void)webAuthenticationDidFailWithError:(NSError *)error
{
    [_webAuthenticationWebViewController stop];
    NSAssert( nil != _delegate, @"Delegate object was lost" );
    [_delegate webAuthenticationDidFailWithError:error];
}

#pragma mark - WKNavigationDelegate Protocol

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    // Forward to the UIWebView controller
    [_webAuthenticationWebViewController webView:webView decidePolicyForNavigationAction:navigationAction decisionHandler:decisionHandler];
}

- (void)webView:(WKWebView *)webView didCommitNavigation:(WKNavigation *)navigation
{
#pragma unused(webView)

    // Start the activity indicator after 2 second delay
    _loading = YES;
    [NSTimer scheduledTimerWithTimeInterval:2.0
                                     target:self
                                   selector:@selector(onStartActivityIndicator:)
                                   userInfo:nil
                                    repeats:NO];
    
    // Forward to the WKWebView controller
    [_webAuthenticationWebViewController webView:webView didCommitNavigation:navigation];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
#pragma unused(webView)

    // Disable the activity indicator
    _loading = NO;
    [_activityIndicator stopAnimating];
    
    // Forward to the WKWebView controller
    [_webAuthenticationWebViewController webView:webView didFinishNavigation:navigation];
}

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
#pragma unused(webView)
    
    // Disable the activity indicator
    _loading = NO;
    [_activityIndicator stopAnimating];

    // Forward to the WKWebView controller
    [_webAuthenticationWebViewController webView:webView didFailNavigation:navigation withError:error];
}

@end
