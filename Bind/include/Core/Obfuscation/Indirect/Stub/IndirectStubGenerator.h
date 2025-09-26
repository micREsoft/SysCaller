#pragma once

#include <QString>
#include <QStringList>
#include <QSettings>
#include <functional>

namespace IndirectObfuscation {

    enum class ResolverCallMethod {
        RegisterPointer = 0,    // Register pointer call via R10
        StackIndirect = 1,      // Stack indirect call (16 byte aligned)
        StackScratch = 2,       // Stack scratch space indirect call
        RegisterShuffle = 3     // Register shuffle call via R10
    };

    inline QString resolverCallMethodToString(ResolverCallMethod method) {
        switch (method) {
            case ResolverCallMethod::RegisterPointer: return "register";
            case ResolverCallMethod::StackIndirect: return "stack";
            case ResolverCallMethod::StackScratch: return "indirect";
            case ResolverCallMethod::RegisterShuffle: return "shuffle";
            default: return "register";
        }
    }

    inline ResolverCallMethod stringToResolverCallMethod(const QString& str) {
        if (str == "stack") return ResolverCallMethod::StackIndirect;
        if (str == "indirect") return ResolverCallMethod::StackScratch;
        if (str == "shuffle") return ResolverCallMethod::RegisterShuffle;
        return ResolverCallMethod::RegisterPointer; // default
    }

    class StubGenerator {
    private:
        QSettings* settings;

    public:
        explicit StubGenerator(QSettings* settings);

        QString obfuscateResolverCall(const QString& originalCall);
    };

}