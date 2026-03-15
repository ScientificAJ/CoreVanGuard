#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <dispatch/dispatch.h>
#import <fcntl.h>

static NSString *auditTokenPath(const es_process_t *process) {
  if (process == NULL || process->executable == NULL || process->executable->path.length == 0) {
    return @"<unknown>";
  }

  return [[NSString alloc] initWithBytes:process->executable->path.data
                                  length:process->executable->path.length
                                encoding:NSUTF8StringEncoding];
}

static NSString *processName(const es_process_t *process) {
  NSString *path = auditTokenPath(process);
  return [path lastPathComponent];
}

static BOOL pathIsUserWritable(NSString *path) {
  return [path hasPrefix:@"/Users/"] || [path hasPrefix:@"/tmp/"] || [path hasPrefix:@"/private/tmp/"];
}

static NSString *signatureState(NSString *path) {
  if ([path hasPrefix:@"/System/"] || [path hasPrefix:@"/usr/"] || [path hasPrefix:@"/Applications/"]) {
    return @"trusted";
  }

  return @"unsigned";
}

static BOOL requestsPersistence(NSString *path) {
  return [path containsString:@"LaunchAgents"] || [path containsString:@"LaunchDaemons"];
}

static BOOL isProtectedPath(NSString *path) {
  return [path containsString:@"CoreVanguard"] || [path containsString:@"Vault"];
}

static BOOL isCanaryPath(NSString *path) {
  return [path containsString:@"CoreVanguardCanary"] || [path containsString:@".corevanguard-canary"];
}

static void emitBehavioralEvent(NSDictionary *payload) {
  NSError *error = nil;
  NSData *json = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&error];
  if (json == nil) {
    NSLog(@"Failed to encode event payload: %@", error);
    return;
  }

  NSString *line = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
  fprintf(stdout, "%s\n", [line UTF8String]);
  fflush(stdout);
}

static void emitExecEvent(const es_message_t *message) {
  NSString *targetPath = auditTokenPath(message->event.exec.target);
  NSDictionary *payload = @{
    @"kind": @"execution_start",
    @"provider_id": @"macos.endpoint_security",
    @"process_id": @(audit_token_to_pid(message->process->audit_token)),
    @"process_name": processName(message->process),
    @"image_path": targetPath,
    @"parent_process": [NSNull null],
    @"launched_from_user_space": @(pathIsUserWritable(targetPath)),
    @"signature_state": signatureState(targetPath),
    @"requested_persistence": @(requestsPersistence(targetPath)),
  };
  emitBehavioralEvent(payload);
}

static void emitOpenEvent(const es_message_t *message) {
  if (message->event.open.file == NULL || message->event.open.file->path.length == 0) {
    return;
  }

  if ((message->event.open.fflag & FWRITE) == 0) {
    return;
  }

  NSString *openedPath = [[NSString alloc]
      initWithBytes:message->event.open.file->path.data
             length:message->event.open.file->path.length
           encoding:NSUTF8StringEncoding];
  NSDictionary *payload = @{
    @"kind": @"file_mutation",
    @"provider_id": @"macos.endpoint_security",
    @"process_id": @(audit_token_to_pid(message->process->audit_token)),
    @"process_name": processName(message->process),
    @"path": openedPath,
    @"bytes_written": @(4096),
    @"entropy": @(0.0),
    @"protected_path": @(isProtectedPath(openedPath)),
    @"canary_file": @(isCanaryPath(openedPath)),
  };
  emitBehavioralEvent(payload);
}

static void emitSignalEvent(const es_message_t *message) {
  NSDictionary *payload = @{
    @"kind": @"self_protection_event",
    @"provider_id": @"macos.endpoint_security",
    @"process_id": @(audit_token_to_pid(message->process->audit_token)),
    @"process_name": processName(message->process),
    @"target": [NSString stringWithFormat:@"pid-%d", audit_token_to_pid(message->event.signal.target->audit_token)],
    @"technique": @"kill_signal",
  };
  emitBehavioralEvent(payload);
}

static void emitPtraceEvent(const es_message_t *message) {
  NSDictionary *payload = @{
    @"kind": @"self_protection_event",
    @"provider_id": @"macos.endpoint_security",
    @"process_id": @(audit_token_to_pid(message->process->audit_token)),
    @"process_name": processName(message->process),
    @"target": [NSString stringWithFormat:@"pid-%d", audit_token_to_pid(message->event.ptrace.target->audit_token)],
    @"technique": @"ptrace",
  };
  emitBehavioralEvent(payload);
}

static void handleMessage(const es_message_t *message) {
  switch (message->event_type) {
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    emitExecEvent(message);
    break;
  }
  case ES_EVENT_TYPE_NOTIFY_OPEN: {
    emitOpenEvent(message);
    break;
  }
  case ES_EVENT_TYPE_NOTIFY_SIGNAL: {
    emitSignalEvent(message);
    break;
  }
  case ES_EVENT_TYPE_NOTIFY_PTRACE: {
    emitPtraceEvent(message);
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
            handleMessage(message);
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
