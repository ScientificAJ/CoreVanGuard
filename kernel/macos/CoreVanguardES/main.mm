#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>

int main(void) {
  @autoreleasepool {
    if (@available(macOS 10.15, *)) {
      NSLog(@"CoreVanguard Endpoint Security compile target booted.");
      NSLog(@"ES subsystem available: %@", ES_EVENT_TYPE_NOTIFY_EXEC ? @"yes" : @"no");
    } else {
      NSLog(@"Endpoint Security requires macOS 10.15 or newer.");
    }
  }

  return 0;
}
