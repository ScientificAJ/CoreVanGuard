# Windows Driver Scaffold

This directory is reserved for the WDK-backed MiniFilter / KMDF project.

Expected future layout:

```text
kernel/windows/
├── CoreVanguardMiniFilter.sln
├── CoreVanguardMiniFilter/
│   ├── CoreVanguardMiniFilter.vcxproj
│   ├── driver.c
│   └── inf/
└── signing/
```

The CI workflow already targets `kernel/windows/CoreVanguardMiniFilter.sln`. Once the Visual Studio solution and project files land, the workflow will restore NuGet dependencies and build it on `windows-2022`.

