#include <fltKernel.h>

PFLT_FILTER gFilterHandle = NULL;

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

  UNREFERENCED_PARAMETER(CompletionContext);

  status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_NORMALIZED |
                                         FLT_FILE_NAME_QUERY_DEFAULT,
                                     &nameInfo);
  if (!NT_SUCCESS(status)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = FltParseFileNameInformation(nameInfo);
  if (NT_SUCCESS(status) && CoreVanguardIsProtectedPath(&nameInfo->Name) &&
      DenyWrite) {
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

  status = FltStartFiltering(gFilterHandle);
  if (!NT_SUCCESS(status)) {
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
  }

  return status;
}
