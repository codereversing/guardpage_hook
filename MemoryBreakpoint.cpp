#include <Windows.h>
#include <stdio.h>

const DWORD func_addr = 0x00401000;
const DWORD func_addr_offset = func_addr + 0x1;

void print_parameters(PCONTEXT debug_context) {
    printf("EAX: %X EBX: %X ECX: %X EDX: %X\n",
        debug_context->Eax, debug_context->Ebx, debug_context->Ecx, debug_context->Edx);
    printf("ESP: %X EBP: %X\n",
        debug_context->Esp, debug_context->Ebp);
    printf("ESI: %X EDI: %X\n",
        debug_context->Esi, debug_context->Edi);
    printf("Parameters\n"
        "HWND: %X\n"
        "text: %s\n"
        "length: %i\n",
        (HWND)(*(DWORD*)(debug_context->Esp + 0x4)),
        (char*)(*(DWORD*)(debug_context->Esp + 0x8)),
        (int)(*(DWORD*)(debug_context->Esp + 0xC)));
    
}

void modify_text(PCONTEXT debug_context) {
    char* text = (char*)(*(DWORD*)(debug_context->Esp + 0x8));
    int length = strlen(text);
    _snprintf(text, length, "REPLACED");
}

LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
    if(ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {        
        ExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD)func_addr) {
            PCONTEXT debug_context = ExceptionInfo->ContextRecord;
            printf("Breakpoint hit!\n");
            print_parameters(debug_context);
            modify_text(debug_context);
        }
        MEMORY_BASIC_INFORMATION mem_info;
        DWORD old_protections = 0;
        VirtualQuery((LPCVOID)func_addr, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
        VirtualProtect(mem_info.BaseAddress, mem_info.RegionSize, mem_info.AllocationProtect | PAGE_GUARD,
            &old_protections);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if(reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        (void)AddVectoredExceptionHandler(1, ExceptionFilter);
        MEMORY_BASIC_INFORMATION mem_info;
        if(AllocConsole()) {
            freopen("CONOUT$", "w", stdout);
            SetConsoleTitle(L"Console");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        DWORD old_protections = 0;
        VirtualQuery((LPCVOID)func_addr, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
        VirtualProtect(mem_info.BaseAddress, mem_info.RegionSize, mem_info.AllocationProtect | PAGE_GUARD,
            &old_protections);
    }
    return TRUE;
}