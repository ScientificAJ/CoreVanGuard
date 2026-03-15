#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <dispatch/dispatch.h>

static NSString *auditTokenPath(const es_process_t *process) {
  if (process == NULL || process->executable == NULL || process->executable->path.length == 0) {
    return @"<unknown>";
  }

  return [[NSString alloc] initWithBytes:process->executable->path.data
                                  length:process->executable->path.length
                                encoding:NSUTF8StringEncoding];
}

static void logMessage(const es_message_t *message) {
  NSString *processPath = auditTokenPath(message->process);

  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    NSString *targetPath = auditTokenPath(message->event.exec.target);
    NSLog(@"[exec] process=%@ target=%@", processPath, targetPath);
    break;
  }
  case ES_EVENT_TYPE_NOTIFY_OPEN: {
    if (message->event.open.file != NULL && message->event.open.file->path.length > 0) {
      NSString *openedPath = [[NSString alloc]
          initWithBytes:message->event.open.file->path.data
                 length:message->event.open.file->path.length
               encoding:NSUTF8StringEncoding];
      NSLog(@"[open] process=%@ path=%@", processPath, openedPath);
    }
    break;
  }
  case ES_EVENT_TYPE_NOTIFY_SIGNAL: {
    NSLog(@"[signal] process=%@ sig=%d target-pid=%d", processPath,
          message->event.signal.sig, audit_token_to_pid(message->event.signal.target->audit_token));
    break;
  }
  case ES_EVENT_TYPE_NOTIFY_PTRACE: {
    NSLog(@"[ptrace] process=%@ target-pid=%d", processPath,
          audit_token_to_pid(message->event.ptrace.target->audit_token));
    break;
  }
  default:
    break;
  }
}

int main(void) {
  @autoreleasepool {
    if (@available(macOS 10.15, *)) {
      __block es_client_t *client = NULL;
      es_new_client_result_t result = es_new_client(
          &client, ^(es_client_t *receivedClient, const es_message_t *message) {
            (void)receivedClient;
            logMessage(message);
          });

      if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        NSLog(@"Failed to create Endpoint Security client: %d", result);
        return 1;
      }

      es_event_type_t subscriptions[] = {
          ES_EVENT_TYPE_NOTIFY_EXEC,
          ES_EVENT_TYPE_NOTIFY_OPEN,
          ES_EVENT_TYPE_NOTIFY_SIGNAL,
          ES_EVENT_TYPE_NOTIFY_PTRACE,
      };

      if (!es_subscribe(client, subscriptions,
                        sizeof(subscriptions) / sizeof(subscriptions[0]))) {
        NSLog(@"Failed to subscribe Endpoint Security events.");
        es_delete_client(client);
        return 1;
      }

      NSLog(@"CoreVanguard Endpoint Security subscriber online.");
      dispatch_main();
    } else {
      NSLog(@"Endpoint Security requires macOS 10.15 or newer.");
    }
  }

  return 0;
}
