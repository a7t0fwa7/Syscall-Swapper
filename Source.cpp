#include <iostream>
#include <Windows.h>
#include <string>
#include <iomanip>
#include <sstream>

std::string ConvertASM(BYTE byte) {
    switch (byte) {
    case 0x4c:
        return "mov r10, rcx";
    case 0xb8:
        return "mov eax, ADDRESS";
    case 0x25:
        return "and eax, ADDRESS";
    case 0x53:
        return "push rbx";
    case 0xf5:
        return "cmc";
    case 0xc3:
        return "ret";
    case 0xcd:
        return "int 0x2e";
    case 0x0f:
        return "syscall";
    default:
        return "?";
    }
}

/*
0:  4c 8b d1                mov    r10,rcx
3:  b8 47 00 0f 64          mov    eax,0x640f0047
8:  25 83 fe 7f 17          and    eax,0x177ffe83
d:  53                      push   rbx
e:  f5                      cmc
f:  c3                      ret
10: cd 2e                   int    0x2e
12: c3                      ret

mov r10, rcx
mov eax, ADDRESS
and eax, ADDRESS
syscall
ret
int 0x2e
ret
*/

int CallFunction()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return 1;

    void* NtAddAtom = (void*)GetProcAddress(ntdll, "NtAddAtom");
    void* NtCreateEvent = (void*)GetProcAddress(ntdll, "NtCreateEvent");

    printf("[) NtAddAtom -> 0x%p\n", NtAddAtom);
    printf("[) NtCreateEvent -> 0x%p\n", NtCreateEvent);

    if (((NTSTATUS(__stdcall*)())NtAddAtom)() != 0xC0000022) {
        printf("NtAddAtom returned a different status\n");
        return 1;
    }

    printf("nt called!\n");

    BYTE Func[24] = { 0 };
    BYTE EventFunc[24] = { 0 };

    RtlCopyMemory(&Func, NtAddAtom, 24);
    RtlCopyMemory(&EventFunc, NtCreateEvent, 24);

    BYTE NtAddAtomSSN = Func[4];
    BYTE NtCreateEventSSN = EventFunc[4];

    printf("SSN NtAddAtom -> %x\n", NtAddAtomSSN);
    printf("SSN NtCreateEventSSN -> %x\n", NtCreateEventSSN);

    printf("[) asm -> NtAddAtom \n");
    for (int i = 0; i < sizeof(Func); i++) {
        std::string ASM = ConvertASM(Func[i]);
        if (ASM != "?") {
            printf("%s\n", ASM.c_str());
        }
    }

    printf("\n Swapping SSN \n");

    DWORD old;
    VirtualProtect(NtAddAtom, sizeof(Func), PAGE_EXECUTE_WRITECOPY, &old);

    memcpy(&Func[4], &NtCreateEventSSN, sizeof(BYTE));
    memcpy(NtAddAtom, Func, sizeof(Func));

    VirtualProtect(NtAddAtom, sizeof(Func), old, NULL);

    if (((NTSTATUS(__stdcall*)())NtAddAtom)() != 0xC0000022) {
        printf("we swapped that bitch \n");
    }

    RtlCopyMemory(&Func, NtAddAtom, 24);
    NtAddAtomSSN = Func[4];

    printf("New syscall stub -> %x\n", NtAddAtomSSN);

	// should probaly swap the stub back
    return 5;
}


int main(void)
{
	return CallFunction();
}
