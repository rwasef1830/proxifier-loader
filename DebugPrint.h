void DebugPrint(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    wchar_t message[1024];
    vswprintf(message, 1024, format, args);
    OutputDebugStringW(message);
}
