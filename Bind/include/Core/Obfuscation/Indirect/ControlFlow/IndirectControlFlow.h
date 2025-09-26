#pragma once

#include <QSettings>
#include <QString>
#include <QStringList>
#include <QRandomGenerator>
#include <QMap>

namespace IndirectObfuscation {

    enum class ControlFlowPattern {
        RegisterBased = 0,  // register based opaque predicate
        ValueBased = 1,     // value based opaque predicate
        FlagBased = 2,      // flag based opaque predicate
        MixedJunkCode = 3   // mixed junk code with opaque predicate
    };

    inline QString controlFlowPatternToString(ControlFlowPattern pattern) {
        switch (pattern) {
            case ControlFlowPattern::RegisterBased: return "register";
            case ControlFlowPattern::ValueBased: return "value";
            case ControlFlowPattern::FlagBased: return "flag";
            case ControlFlowPattern::MixedJunkCode: return "mixed";
            default: return "register";
        }
    }

    inline ControlFlowPattern stringToControlFlowPattern(const QString& str) {
        if (str == "value") return ControlFlowPattern::ValueBased;
        if (str == "flag") return ControlFlowPattern::FlagBased;
        if (str == "mixed") return ControlFlowPattern::MixedJunkCode;
        return ControlFlowPattern::RegisterBased; // default
    }

    class ControlFlow {
    private:
        QSettings* settings;

    public:
        explicit ControlFlow(QSettings* settings);

        QString generateControlFlowObfuscation();
    };

}
