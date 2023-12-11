@Echo Off
cd %~dp0
mkdir bin
x86_64-w64-mingw32-g++.exe -shared -municode -obin\ProxifierBufferSmallifierLoaderHook.dll ProxifierBufferSmallifierLoaderHook.cpp -lws2_32 -I include -I include -L . -lMinHook
x86_64-w64-mingw32-g++.exe -municode -mwindows -obin\ProxifierBufferSmallifierLoader.exe ProxifierBufferSmallifierLoader.cpp
copy MinHook.dll bin
