#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QSettings>
#include <QSet>

namespace DirectObfuscation {
class ControlFlow {
public:
    explicit ControlFlow(QSettings* settings = nullptr);
    QStringList generateOpaquePredicates(const QString& labelPrefix);
    QStringList generateBogusControlFlow(const QString& labelPrefix);
    QStringList generateIndirectJumps(const QString& labelPrefix);
    QStringList generateConditionalBranches(const QString& labelPrefix);
    void setSettings(QSettings* settings);
    QString generateRandomLabel(const QString& prefix);
    QStringList wrapWithControlFlow(const QStringList& originalCode, const QString& labelPrefix);
    bool isOpaquePredicatesEnabled();
    bool isBogusControlFlowEnabled();
    bool isIndirectJumpsEnabled();
    bool isConditionalBranchesEnabled();
    int getControlFlowComplexity();

private:
    QSettings* settings;
    QSet<QString> usedLabels;
    int getRandomInt(int min, int max);
    QString getRandomRegister();
    QString getRandomCondition();
    QStringList generateAlwaysTrueCondition();
    QStringList generateAlwaysFalseCondition();
    QStringList generateComplexPredicate();
};
}
