#include <Core/Obfuscation/IndirectObfuscation.h>
#include <Core/Obfuscation/Indirect/Indirect.h>
#include <Core/Obfuscation/Shared/Shared.h>
#include <Core/Utils/Common.h>

IndirectObfuscationManager::IndirectObfuscationManager(QSettings* settings)
    : settings(settings)
    , outputCallback(nullptr)
{}

void IndirectObfuscationManager::setOutputCallback(std::function<void(const QString&)> callback)
{
    outputCallback = callback;
}

void IndirectObfuscationManager::logMessage(const QString& message)
{
    if (outputCallback)
    {
        outputCallback(message);
    }

    qDebug() << "IndirectObfuscation:" << message;
}

QString IndirectObfuscationManager::getIndirectPrefix()
{
    return "SysIndirect";
}

bool IndirectObfuscationManager::isIndirectMode()
{
    return settings->value("general/indirect_assembly", false).toBool();
}

bool IndirectObfuscationManager::generateIndirectObfuscation()
{
    logMessage("Starting Indirect Obfuscation...");

    bool isKernel = settings->value("general/syscall_mode", "Nt").toString() == "Zw";

    QString asmPath = isKernel ?
                      PathUtils::getSysCallerKPath() + "/Wrapper/src/SysCaller.asm" :
                      PathUtils::getSysCallerPath() + "/Wrapper/src/SysCaller.asm";

    QString headerPath = isKernel ?
                         PathUtils::getSysCallerKPath() + "/Wrapper/SysK/SysKFunctions.h" :
                         PathUtils::getSysCallerPath() + "/Wrapper/Sys/SysFunctions.h";

    return processIndirectAssemblyFile(asmPath, headerPath);
}

bool IndirectObfuscationManager::processIndirectAssemblyFile(const QString& asmPath, const QString& headerPath)
{
    QFile asmFile(asmPath);

    if (!asmFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        logMessage("Failed to open Assembly File: " + asmPath);
        return false;
    }

    QTextStream in(&asmFile);
    QStringList content = in.readAll().split('\n');
    asmFile.close();

    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    QString indirectPrefix = getIndirectPrefix();
    QMap<QString, QStringList> indirectStubs;
    QSet<QString> usedNames;
    QMap<QString, QString> syscallMap; /* original -> obfuscated */

    QStringList currentStub;
    QString currentSyscall;
    bool inStub = false;
    for (const QString& line : content)
    {
        QRegularExpression procRegex(QString("(%1\\w+)\\s+PROC").arg(indirectPrefix));
        QRegularExpressionMatch procMatch = procRegex.match(line);

        if (procMatch.hasMatch())
        {
            currentSyscall = procMatch.captured(1);
            inStub = true;
            currentStub.clear();
            currentStub << line;

            if (useAllSyscalls || selectedSyscalls.contains(currentSyscall))
            {
                indirectStubs[currentSyscall] = currentStub;
            }
        }
        else if (inStub)
        {
            currentStub << line;

            if (line.contains(" ENDP"))
            {
                inStub = false;

                if (useAllSyscalls || selectedSyscalls.contains(currentSyscall))
                {
                    indirectStubs[currentSyscall] = currentStub;
                }
            }
        }
    }
    if (!indirectStubs.isEmpty())
    {
        SharedObfuscation::NameGenerator nameGen(settings);
        int indirectPrefixLength = settings->value("obfuscation/indirect_syscall_prefix_length",
                                                   settings->value("obfuscation/syscall_prefix_length", 8).toInt()).toInt();
        int indirectNumberLength = settings->value("obfuscation/indirect_syscall_number_length",
                                                   settings->value("obfuscation/syscall_number_length", 6).toInt()).toInt();

        for (auto it = indirectStubs.begin(); it != indirectStubs.end(); ++it)
        {
            const QString& original = it.key();

            if (!syscallMap.contains(original))
            {
                syscallMap[original] = nameGen.generateRandomName(usedNames, indirectPrefixLength, indirectNumberLength);
            }
        }
    }
    for (auto it = indirectStubs.begin(); it != indirectStubs.end(); ++it)
    {
        QStringList obfuscatedStub;
        bool inProcBlock = false;
        bool pendingEncString = false;
        QByteArray pendingEncBytes;
        int pendingPlainLen = 0;
        quint8 pendingKey = 0;
        bool encAdjustActive = false; /* when true, convert next add rsp,32 to add rsp,64 */

        for (const QString& line : it.value())
        {
            QString obfuscatedLine = line;

            if (line.contains(" PROC"))
            {
                inProcBlock = true;
                obfuscatedStub << line;
                continue;
            }

            if (line.contains(" ENDP"))
            {
                inProcBlock = false;
                pendingEncString = false;
                pendingEncBytes.clear();
                pendingPlainLen = 0;
                obfuscatedStub << line;
                continue;
            }

            if (inProcBlock)
            {
                if (settings->value("obfuscation/indirect_enable_junk", true).toBool())
                {
                    IndirectObfuscation::JunkGenerator JunkGenerator(settings);
                    QString junkCode = JunkGenerator.generateRegisterSafeJunk();

                    if (!junkCode.isEmpty())
                    {
                        QStringList junkLines = junkCode.split('\n');

                        for (const QString& junkLine : junkLines)
                        {
                            if (!junkLine.trimmed().isEmpty())
                            {
                                obfuscatedStub << "    " + junkLine.trimmed();
                            }
                        }
                    }
                }

                if (settings->value("obfuscation/indirect_encrypt_strings", false).toBool())
                {
                    QRegularExpression strRx(R"(^\s*lea\s+rcx,\s*\[(\w+)_str\]\s*$)",
                                            QRegularExpression::CaseInsensitiveOption);
                    auto m = strRx.match(line);

                    if (m.hasMatch())
                    {
                        QString label = m.captured(1);
                        QByteArray plain = label.toUtf8();
                        plain.append('\0');

                        if (plain.size() <= 32)
                        {
                            pendingKey = static_cast<quint8>(QRandomGenerator::global()->bounded(1, 256));
                            pendingEncBytes = QByteArray(plain);

                            for (int i = 0; i < pendingEncBytes.size(); ++i)
                                pendingEncBytes[i] = pendingEncBytes[i] ^ pendingKey;

                            pendingPlainLen = plain.size();
                            pendingEncString = true;
                            continue;
                        }
                    }
                }

                /* if we have pending enc string and see shadow space reservation,
                   emit the build+decrypt into shadow space */
                if (pendingEncString && line.trimmed().startsWith("sub rsp, 32"))
                {
                    /* replace with sub rsp, 64 to allocate extra 32 bytes (shadow + our buffer) */
                    obfuscatedStub << "    sub rsp, 64";
                    encAdjustActive = true;

                    /* now emit write+decrypt sequence using only rax, rcx, r11, r8b;
                       buffer base is [rsp+20h] */
                    obfuscatedStub << "    ; Build decrypted resolver string in shadow space";
                    int lblId = QRandomGenerator::global()->bounded(1000, 999999);
                    QString loopLbl = QString("dec_loop_cf_%1").arg(lblId);
                    QString doneLbl = QString("dec_done_cf_%1").arg(lblId);

                    /* write encrypted qwords into [rsp+off] */
                    for (int off = 0; off < 32; off += 8)
                    {
                        quint64 q = 0;

                        for (int b = 0; b < 8; ++b)
                        {
                            int idx = off + b;
                            unsigned char val = 0;

                            if (idx < pendingEncBytes.size())
                                val = static_cast<unsigned char>(pendingEncBytes[idx]);

                            q |= (static_cast<quint64>(val) << (8 * b));
                        }

                        QString hex = QString::number(static_cast<qulonglong>(q), 16).toUpper();
                        while (hex.length() < 16) hex.prepend('0');

                        obfuscatedStub << QString("    mov rax, 0%1h").arg(hex);

                        if (off == 0)
                        {
                            obfuscatedStub << "    mov qword ptr [rsp+20h], rax";
                        }
                        else
                        {
                            obfuscatedStub << QString("    mov qword ptr [rsp+20h+%1], rax").arg(off);
                        }
                    }

                    obfuscatedStub << QString("    mov r11d, %1").arg(pendingPlainLen);

                    {
                        QString khex = QString::number(pendingKey, 16).toUpper();
                        if (khex.length() < 2) khex.prepend('0');
                        obfuscatedStub << QString("    mov al, 0%1h").arg(khex);
                    }

                    obfuscatedStub << "    ; decrypt in place: for i in [0..len) shadow[i] ^= al";
                    obfuscatedStub << "    xor rcx, rcx";
                    obfuscatedStub << loopLbl + ":";
                    obfuscatedStub << "    cmp rcx, r11";
                    obfuscatedStub << "    jae " + doneLbl;
                    obfuscatedStub << "    mov r8b, byte ptr [rsp+rcx+20h]";
                    obfuscatedStub << "    xor r8b, al";
                    obfuscatedStub << "    mov byte ptr [rsp+rcx+20h], r8b";
                    obfuscatedStub << "    inc rcx";
                    obfuscatedStub << "    jmp " + loopLbl;
                    obfuscatedStub << doneLbl + ":";

                    obfuscatedStub << "    lea rcx, [rsp+20h]"; /* rcx = decrypted buffer out of callee home space */

                    pendingEncString = false;
                    pendingEncBytes.clear();
                    pendingPlainLen = 0;
                    continue;
                }

                if (encAdjustActive && line.trimmed().startsWith("add rsp, 32"))
                {
                    obfuscatedStub << "    add rsp, 64";
                    encAdjustActive = false;
                    continue;
                }

                if (line.contains("call GetSyscallNumber"))
                {
                    IndirectObfuscation::StubGenerator stub(settings);
                    obfuscatedLine = stub.obfuscateResolverCall(line);
                }

                if (settings->value("obfuscation/indirect_enable_control_flow", false).toBool())
                {
                    IndirectObfuscation::ControlFlow cf(settings);
                    QString controlFlowCode = cf.generateControlFlowObfuscation();

                    if (!controlFlowCode.isEmpty())
                    {
                        QStringList controlFlowLines = controlFlowCode.split('\n');

                        for (const QString& flowLine : controlFlowLines)
                        {
                            if (!flowLine.trimmed().isEmpty())
                            {
                                obfuscatedStub << "    " + flowLine.trimmed();
                            }
                        }
                    }
                }
            }

            obfuscatedStub << obfuscatedLine;
        }
        QStringList renamedStub;

        for (const QString& sLine : obfuscatedStub)
        {
            QString newLine = sLine;
            QRegularExpression nameRx(QString("((%1\\w+))\\s+(PROC|ENDP)").arg(indirectPrefix));
            auto m = nameRx.match(newLine);

            if (m.hasMatch())
            {
                QString originalName = m.captured(1);

                if (syscallMap.contains(originalName))
                {
                    newLine = newLine.replace(originalName, syscallMap.value(originalName));
                }
            }

            renamedStub << newLine;
        }

        it.value() = renamedStub;
    }
    QFile outAsmFile(asmPath);

    if (!outAsmFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        logMessage("Failed to write Assembly File: " + asmPath);
        return false;
    }

    QTextStream out(&outAsmFile);
    bool inProcessedStub = false;
    bool injectedAliases = false;
    QString currentStubName;

    for (int i = 0; i < content.size(); ++i)
    {
        const QString& line = content[i];

        if (!injectedAliases && line.trimmed().compare(".code", Qt::CaseInsensitive) == 0)
        {
            out << line << "\n\n";

            if (!syscallMap.isEmpty())
            {
                out << "; Public Declarations\n";

                for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
                {
                    out << QString("PUBLIC %1\n").arg(it.value());
                }

                out << "\n; Export Aliases\n";

                for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
                {
                    out << QString("ALIAS <%1> = <%2>\n").arg(it.key()).arg(it.value());
                }

                out << "\n";
            }

            injectedAliases = true;
            continue;
        }

        QRegularExpression procRegex(QString("(%1\\w+)\\s+PROC").arg(indirectPrefix));
        QRegularExpressionMatch procMatch = procRegex.match(line);

        if (procMatch.hasMatch())
        {
            QString stubName = procMatch.captured(1);

            if (indirectStubs.contains(stubName))
            {
                inProcessedStub = true;
                currentStubName = stubName;

                for (const QString& stubLine : indirectStubs[stubName])
                {
                    out << stubLine << "\n";
                }

                continue;
            }
        }

        if (inProcessedStub && line.contains(" ENDP"))
        {
            inProcessedStub = false;
            currentStubName.clear();
            continue;
        }

        if (inProcessedStub)
        {
            continue;
        }

        out << line << "\n";
    }
    outAsmFile.close();

    if (!updateIndirectHeaderFile(headerPath, syscallMap))
    {
        logMessage("Failed to update Header File for indirect obfuscation");
        return false;
    }

    bool bindingsEnabled = settings->value("general/bindings_enabled", false).toBool();
    bool isKernel = settings->value("general/syscall_mode", "Nt").toString() == "Zw";

    if (bindingsEnabled && !isKernel)
    {
        QString defPath = PathUtils::getSysCallerPath() + "/Wrapper/SysCaller.def";
        QStringList obfuscatedNames;

        for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
        {
            obfuscatedNames << it.value();
        }

        if (!updateDefFile(defPath, obfuscatedNames))
        {
            logMessage("Failed to update DEF File for indirect obfuscation");
            return false;
        }
    }

    logMessage("Indirect Obfuscation completed successfully!");
    return true;
}

bool IndirectObfuscationManager::updateIndirectHeaderFile(const QString& headerPath,
                                                          const QMap<QString, QString>& syscallMap)
{
    QFile headerFile(headerPath);

    if (!headerFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        logMessage("Failed to open Header File: " + headerPath);
        return false;
    }

    QTextStream in(&headerFile);
    QStringList headerContent = in.readAll().split('\n');
    headerFile.close();

    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();
    bool useAllSyscalls = selectedSyscalls.isEmpty();
    QString indirectPrefix = getIndirectPrefix();
    QStringList newHeaderContent;
    bool headerPartEnded = false;
    bool skipBlock = false;
    QString currentFunc;

    for (const QString& line : headerContent)
    {
        if (!headerPartEnded && (
            line.contains(QString("NTSTATUS %1").arg(indirectPrefix)) ||
            line.contains(QString("ULONG %1").arg(indirectPrefix)) ||
            line.contains(QString("BOOLEAN %1").arg(indirectPrefix)) ||
            line.contains(QString("VOID %1").arg(indirectPrefix)) ||
            line.contains("#ifdef __cplusplus")
        ))
        {
            headerPartEnded = true;
        }

        if (!headerPartEnded)
        {
            newHeaderContent << line;
            continue;
        }

        /* preserve c++ guards and extern blocks */
        if (line.contains("#ifdef __cplusplus") || line.contains("extern \"C\"") ||
            line.trimmed() == "{" || line.trimmed() == "}" || line.contains("#endif"))
        {
            newHeaderContent << line;
            continue;
        }

        if (line.contains(QString("%1").arg(indirectPrefix)))
        {
            QRegularExpression regex(QString(R"((?:extern\s+\"C\"\s+)?(?:NTSTATUS|ULONG|BOOLEAN|VOID) ((?:%1)\w+)\()")
                                           .arg(indirectPrefix));
            auto m = regex.match(line);

            if (m.hasMatch())
            {
                QString originalName = m.captured(1);
                currentFunc = originalName;

                if (useAllSyscalls || selectedSyscalls.contains(currentFunc))
                {
                    skipBlock = false;

                    if (syscallMap.contains(originalName))
                    {
                        QString newLine = line;
                        QString obf = syscallMap.value(originalName);
                        newLine = newLine.replace(originalName, obf);
                        newLine = newLine.replace("extern \"C\" ", "");
                        newHeaderContent << newLine;
                    }
                }
                else
                {
                    skipBlock = true;
                }

                continue;
            }
        }

        if (!skipBlock)
        {
            newHeaderContent << line;
        }
        else if (line.trimmed() == ");")
        {
            skipBlock = false;
        }
    }
    newHeaderContent << "";
    newHeaderContent << "/* Syscall Name Mappings (Indirect) */";

    for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it)
    {
        newHeaderContent << QString("#define %1 %2").arg(it.key()).arg(it.value());
    }

    QStringList cleaned;
    bool prevEmpty = false;

    for (const QString& l : newHeaderContent)
    {
        if (l.trimmed().isEmpty())
        {
            if (!prevEmpty)
            {
                cleaned << l;
                prevEmpty = true;
            }
        }
        else
        {
            cleaned << l;
            prevEmpty = false;
        }
    }

    QFile outHeaderFile(headerPath);

    if (!outHeaderFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        logMessage("Failed to write Header File: " + headerPath);
        return false;
    }

    QTextStream hout(&outHeaderFile);
    hout << cleaned.join("\n");
    outHeaderFile.close();
    return true;
}

bool IndirectObfuscationManager::updateDefFile(const QString& defPath,
                                               const QStringList& obfuscatedNames)
{
    QFile defFile(defPath);

    if (!defFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        logMessage("Failed to write DEF File: " + defPath);
        return false;
    }

    QTextStream out(&defFile);
    out << "LIBRARY SysCaller\n";
    out << "EXPORTS\n";

    for (const QString& name : obfuscatedNames)
    {
        out << "    " << name << "\n";
    }

    if (settings && settings->value("general/indirect_assembly", false).toBool())
    {
        out << "    GetSyscallNumber\n";
        out << "    InitializeResolver\n";
        out << "    CleanupResolver\n";
    }

    defFile.close();
    return true;
}