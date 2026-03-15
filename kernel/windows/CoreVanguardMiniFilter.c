#include <fltKernel.h>
#include <ntstrsafe.h>

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;

#define COREVANGUARD_PORT_NAME L"\\CoreVanguardPort"

typedef struct _CVG_TELEMETRY_MESSAGE {
  ULONG ProcessId;
  ULONG MajorFunction;
  BOOLEAN WriteIntent;
  BOOLEAN Blocked;
  WCHAR Path[260];
} CVG_TELEMETRY_MESSAGE, *PCVG_TELEMETRY_MESSAGE;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
CoreVanguardUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
CoreVanguardInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                          _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                          _In_ DEVICE_TYPE VolumeDeviceType,
                          _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS
CoreVanguardPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                      _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _Outptr_result_maybenull_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS
CoreVanguardPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
                     _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _Outptr_result_maybenull_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS
CoreVanguardPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                              _In_ PCFLT_RELATED_OBJECTS FltObjects,
                              _Outptr_result_maybenull_ PVOID *CompletionContext);

NTSTATUS
CoreVanguardPortConnect(_In_ PFLT_PORT ClientPort,
                        _In_opt_ PVOID ServerPortCookie,
                        _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                        _In_ ULONG SizeOfContext,
                        _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);

VOID
CoreVanguardPortDisconnect(_In_opt_ PVOID ConnectionCookie);

NTSTATUS
CoreVanguardPortMessage(_In_opt_ PVOID PortCookie,
                        _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                        _In_ ULONG InputBufferLength,
                        _Out_writes_bytes_to_opt_(OutputBufferLength,
                                                  *ReturnOutputBufferLength)
                            PVOID OutputBuffer,
                        _In_ ULONG OutputBufferLength,
                        _Out_ PULONG ReturnOutputBufferLength);

NTSTATUS
CoreVanguardCreateCommunicationPort(VOID);

VOID
CoreVanguardDestroyCommunicationPort(VOID);

VOID
CoreVanguardSendTelemetry(_In_ PFLT_CALLBACK_DATA Data,
                          _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo,
                          _In_ BOOLEAN WriteIntent,
                          _In_ BOOLEAN Blocked);

static CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, CoreVanguardPreCreate, NULL},
    {IRP_MJ_WRITE, 0, CoreVanguardPreWrite, NULL},
    {IRP_MJ_SET_INFORMATION, 0, CoreVanguardPreSetInformation, NULL},
    {IRP_MJ_OPERATION_END}};

static CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks,
    CoreVanguardUnload,        CoreVanguardInstanceSetup, NULL, NULL,
    NULL,                      NULL,                      NULL, NULL,
    NULL,                      NULL};

static BOOLEAN
CoreVanguardIsProtectedPath(_In_ PUNICODE_STRING Name) {
  if (Name == NULL || Name->Buffer == NULL) {
    return FALSE;
  }

  if (wcsstr(Name->Buffer, L"CoreVanguard") != NULL ||
      wcsstr(Name->Buffer, L"Vault") != NULL) {
    return TRUE;
  }

  return FALSE;
}

static FLT_PREOP_CALLBACK_STATUS
CoreVanguardInspectName(_Inout_ PFLT_CALLBACK_DATA Data,
                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _Outptr_result_maybenull_ PVOID *CompletionContext,
                        _In_ BOOLEAN DenyWrite) {
  NTSTATUS status;
  PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
  BOOLEAN blocked = FALSE;
  BOOLEAN protectedPath = FALSE;

  UNREFERENCED_PARAMETER(CompletionContext);

  status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED |
                                         FLT_FILE_NAME_QUERY_DEFAULT,
                                     &nameInfo);
  if (!NT_SUCCESS(status)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (NT_SUCCESS(status)) {
    protectedPath = CoreVanguardIsProtectedPath(&nameInfo->Name);
    blocked = protectedPath && DenyWrite;
    CoreVanguardSendTelemetry(Data, nameInfo, DenyWrite, blocked);
  }

  if (blocked) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_COMPLETE;
  }

  FltReleaseFileNameInformation(nameInfo);
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
CoreVanguardInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                          _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                          _In_ DEVICE_TYPE VolumeDeviceType,
                          _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(Flags);
  UNREFERENCED_PARAMETER(VolumeDeviceType);

  if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
      VolumeFilesystemType != FLT_FSTYPE_REFS) {
    return STATUS_FLT_DO_NOT_ATTACH;
  }

  return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
CoreVanguardPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                      _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _Outptr_result_maybenull_ PVOID *CompletionContext) {
  ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext
                                  ->DesiredAccess;
  BOOLEAN writeIntent = BooleanFlagOn(desiredAccess,
                                      FILE_WRITE_DATA | FILE_APPEND_DATA |
                                          DELETE | WRITE_DAC | WRITE_OWNER);

  return CoreVanguardInspectName(Data, FltObjects, CompletionContext,
                                 writeIntent);
}

FLT_PREOP_CALLBACK_STATUS
CoreVanguardPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
                     _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _Outptr_result_maybenull_ PVOID *CompletionContext) {
  return CoreVanguardInspectName(Data, FltObjects, CompletionContext, TRUE);
}

FLT_PREOP_CALLBACK_STATUS
CoreVanguardPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                              _In_ PCFLT_RELATED_OBJECTS FltObjects,
                              _Outptr_result_maybenull_ PVOID *CompletionContext) {
  FILE_INFORMATION_CLASS fileInformationClass =
      Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
  BOOLEAN renameOrDelete =
      fileInformationClass == FileDispositionInformation ||
      fileInformationClass == FileDispositionInformationEx ||
      fileInformationClass == FileRenameInformation ||
      fileInformationClass == FileRenameInformationEx;

  return CoreVanguardInspectName(Data, FltObjects, CompletionContext,
                                 renameOrDelete);
}

NTSTATUS
CoreVanguardUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
  UNREFERENCED_PARAMETER(Flags);

  CoreVanguardDestroyCommunicationPort();

  if (gFilterHandle != NULL) {
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
  }

  return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;

  UNREFERENCED_PARAMETER(RegistryPath);

  status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = CoreVanguardCreateCommunicationPort();
  if (!NT_SUCCESS(status)) {
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
    return status;
  }

  status = FltStartFiltering(gFilterHandle);
  if (!NT_SUCCESS(status)) {
    CoreVanguardDestroyCommunicationPort();
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
  }

  return status;
}

NTSTATUS
CoreVanguardPortConnect(_In_ PFLT_PORT ClientPort,
                        _In_opt_ PVOID ServerPortCookie,
                        _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                        _In_ ULONG SizeOfContext,
                        _Outptr_result_maybenull_ PVOID *ConnectionPortCookie) {
  UNREFERENCED_PARAMETER(ServerPortCookie);
  UNREFERENCED_PARAMETER(ConnectionContext);
  UNREFERENCED_PARAMETER(SizeOfContext);
  UNREFERENCED_PARAMETER(ConnectionPortCookie);

  gClientPort = ClientPort;
  return STATUS_SUCCESS;
}

VOID
CoreVanguardPortDisconnect(_In_opt_ PVOID ConnectionCookie) {
  UNREFERENCED_PARAMETER(ConnectionCookie);

  if (gFilterHandle != NULL && gClientPort != NULL) {
    FltCloseClientPort(gFilterHandle, &gClientPort);
  }
}

NTSTATUS
CoreVanguardPortMessage(_In_opt_ PVOID PortCookie,
                        _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                        _In_ ULONG InputBufferLength,
                        _Out_writes_bytes_to_opt_(OutputBufferLength,
                                                  *ReturnOutputBufferLength)
                            PVOID OutputBuffer,
                        _In_ ULONG OutputBufferLength,
                        _Out_ PULONG ReturnOutputBufferLength) {
  UNREFERENCED_PARAMETER(PortCookie);
  UNREFERENCED_PARAMETER(InputBuffer);
  UNREFERENCED_PARAMETER(InputBufferLength);
  UNREFERENCED_PARAMETER(OutputBuffer);
  UNREFERENCED_PARAMETER(OutputBufferLength);

  if (ReturnOutputBufferLength != NULL) {
    *ReturnOutputBufferLength = 0;
  }

  return STATUS_SUCCESS;
}

NTSTATUS
CoreVanguardCreateCommunicationPort(VOID) {
  NTSTATUS status;
  OBJECT_ATTRIBUTES objectAttributes;
  PSECURITY_DESCRIPTOR securityDescriptor = NULL;
  UNICODE_STRING portName;

  RtlInitUnicodeString(&portName, COREVANGUARD_PORT_NAME);

  status =
      FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  InitializeObjectAttributes(&objectAttributes, &portName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             securityDescriptor);

  status = FltCreateCommunicationPort(
      gFilterHandle, &gServerPort, &objectAttributes, NULL,
      CoreVanguardPortConnect, CoreVanguardPortDisconnect,
      CoreVanguardPortMessage, 1);

  FltFreeSecurityDescriptor(securityDescriptor);
  return status;
}

VOID
CoreVanguardDestroyCommunicationPort(VOID) {
  if (gFilterHandle != NULL && gClientPort != NULL) {
    FltCloseClientPort(gFilterHandle, &gClientPort);
  }

  if (gServerPort != NULL) {
    FltCloseCommunicationPort(gServerPort);
    gServerPort = NULL;
  }
}

VOID
CoreVanguardSendTelemetry(_In_ PFLT_CALLBACK_DATA Data,
                          _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo,
                          _In_ BOOLEAN WriteIntent,
                          _In_ BOOLEAN Blocked) {
  CVG_TELEMETRY_MESSAGE message;
  ULONG replyLength = 0;

  if (gFilterHandle == NULL || gClientPort == NULL) {
    return;
  }

  RtlZeroMemory(&message, sizeof(message));
  message.ProcessId = HandleToULong(FltGetRequestorProcessId(Data));
  message.MajorFunction = Data->Iopb->MajorFunction;
  message.WriteIntent = WriteIntent;
  message.Blocked = Blocked;

  if (NameInfo != NULL && NameInfo->Name.Buffer != NULL &&
      NameInfo->Name.Length > 0) {
    RtlStringCchCopyNW(message.Path, RTL_NUMBER_OF(message.Path),
                       NameInfo->Name.Buffer,
                       NameInfo->Name.Length / sizeof(WCHAR));
  }

  FltSendMessage(gFilterHandle, &gClientPort, &message, sizeof(message), NULL,
                 &replyLength, NULL);
}
