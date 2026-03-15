# Windows Driver

This directory now contains a real MiniFilter source file at `CoreVanguardMiniFilter.c` with:

- `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION` callbacks
- protected-path denial logic for write, rename, and delete attempts
- NTFS/ReFS instance filtering
- standard `DriverEntry`, unload, and filter registration flow

Expected future layout:

```text
kernel/windows/
├── CoreVanguardMiniFilter.sln
├── CoreVanguardMiniFilter/
│   ├── CoreVanguardMiniFilter.vcxproj
│   ├── CoreVanguardMiniFilter.c
│   └── inf/
└── signing/
```

The CI workflow still targets `kernel/windows/CoreVanguardMiniFilter.sln`. The remaining work is to add the Visual Studio solution/project files, communication-port wiring to the Rust engine, and the process-protection callback path.
