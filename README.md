## ProxifierBufferSmallifierLoader

This application is a stopgap measure for a missing feature in Proxifier (https://www.proxifier.com).

It's a loader which loads Proxifier.exe and then injects `ProxifierBufferSmallifierLoaderHook.dll` which uses `MinHook.dll` (https://github.com/TsudaKageyu/minhook) to intercept a few WSA socket functions to shrink the send/receive buffer sizes.

Along with setting the buffer sizes on the proxy app itself, this prevents proxy upload buffer bloat which leads to time out on large uploads.

# Symptom of this issue:

When using Proxifier and a proxy app, trying to upload any file jumps to 90% immediately, then hangs as the real upload happens in the background by the proxy. Sometimes the uploading app waits for completion and sometimes it times out. This issue also messes up upload speed tests.

# To solve this issue:

1. Unzip the release into proxifier directory.
2. Rename `Proxifier.exe` to `ProxifierOriginal.exe`
3. Rename `ProxifierBufferSmallifierLoader.exe` to `Proxifier.exe`
4. Setup your proxy app to shrink down its listening socket send buffer to 16384 bytes. Note: The buffer must be set on the listening socket, not the accepted socket!
5. If this proxy app connects to another app on localhost, then its remote side socket also needs the send buffer shrunk to 16384. Note: The buffer must be set *before* connecting.
6. Run the new `Proxifier.exe`
