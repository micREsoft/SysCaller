#include "include/Core/Obfuscation/Indirect/Stub/IndirectStubGenerator.h"
#include <QRandomGenerator>
#include <QMap>
#include <QStringList>

IndirectObfuscation::StubGenerator::StubGenerator(QSettings* settings)
    : settings(settings)
{}

QString IndirectObfuscation::StubGenerator::obfuscateResolverCall(const QString& originalCall)
{
    if (settings->value("obfuscation/indirect_obfuscate_calls", true).toBool())
    {
        QString method = settings->value("obfuscation/indirect_resolver_method", "random").toString();

        ResolverCallMethod callMethod;

        if (method == "random")
        {
            int randomValue = QRandomGenerator::global()->bounded(4);
            callMethod = static_cast<ResolverCallMethod>(randomValue);
        }
        else
        {
            callMethod = stringToResolverCallMethod(method);
        }

        switch (callMethod)
        {
            case ResolverCallMethod::RegisterPointer:
                return "    ; RegPtr_R10_Call\n"
                       "    lea r10, [GetSyscallNumber]\n"
                       "    call r10";

            case ResolverCallMethod::StackIndirect:
                return "    ; StackIndirect_Aligned\n"
                       "    sub rsp, 16\n"
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp], rax\n"
                       "    call qword ptr [rsp]\n"
                       "    add rsp, 16";

            case ResolverCallMethod::StackScratch:
                return "    ; StackScratchIndirect\n"
                       "    lea rax, [GetSyscallNumber]\n"
                       "    mov [rsp-8], rax\n"
                       "    lea rax, [rsp-8]\n"
                       "    call qword ptr [rax]";

            case ResolverCallMethod::RegisterShuffle:
                return "    ; RegShuffle_R10_Call\n"
                       "    push r10\n"
                       "    lea r10, [GetSyscallNumber]\n"
                       "    call r10\n"
                       "    pop r10";
        }
    }

    return originalCall;
}
