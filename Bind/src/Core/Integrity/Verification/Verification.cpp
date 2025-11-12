#include <Core/Integrity/Integrity.h>
#include <Core/Utils/Common.h>
#include <pe-parse/parse.h>

Verification::Verification()
    : QObject(nullptr)
    , pe(nullptr)
    , imageBase(0)
    , processedCount(0)
{}

void Verification::setOutputCallback(std::function<void(const QString&)> callback)
{
    outputCallback = callback;
}

void Verification::outputProgress(const QString& message)
{
    if (outputCallback)
    {
        /* for important system messages (startup, summary, errors) send immediately */
        /* for result details (syscall names, status, offsets, etc.) batch them for performance */
        bool isImportantMessage = message.isEmpty() || 
                                  message.contains("Testing") || 
                                  message.contains("Summary") || 
                                  message.contains("Starting") || 
                                  message.contains("Using DLL") ||
                                  message.contains("Found") ||
                                  message.contains("Failed to open") ||
                                  message.contains("Error Testing");
        
        if (isImportantMessage)
        {
            flushOutputBuffer();
            outputCallback(message);
        }
        else
        {
            outputBuffer.append(message);
            
            if (outputBuffer.size() >= OUTPUT_BATCH_SIZE)
            {
                flushOutputBuffer();
            }
        }
    }
}

void Verification::flushOutputBuffer()
{
    if (outputCallback && !outputBuffer.isEmpty())
    {
        for (const QString& line : outputBuffer)
        {
            outputCallback(line);
        }
        outputBuffer.clear();
    }
}

int Verification::run(int argc, char* argv[])
{
    return runWithDllPaths(QStringList() << Constants::DEFAULT_NTDLL_PATH);
}

int Verification::runWithDllPaths(const QStringList& dllPaths)
{
    qDebug() << QString("Verification::runWithDllPaths() called with paths: %1")
                      .arg(dllPaths.join(", "));
    /* reset performance counters and buffers */
    outputBuffer.clear();
    processedCount = 0;

    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");

    qDebug() << QString("Syscall Mode: %1, Kernel Mode: %2")
                      .arg(syscallMode)
                      .arg(isKernelMode);

    QStringList dllPathsToUse = dllPaths;

    if (dllPathsToUse.isEmpty())
    {
        dllPathsToUse << Constants::DEFAULT_NTDLL_PATH;
    }

    this->dllPaths = dllPathsToUse;
    this->dllPath = dllPathsToUse.first();

    qDebug() << QString("Using DLL Paths: %1").arg(dllPathsToUse.join(", "));

    outputProgress(Colors::OKBLUE() + QString("Starting Verification Check...") + Colors::ENDC());
    outputProgress(Colors::OKBLUE() + QString("Using DLL Paths: %1")
                          .arg(dllPathsToUse.join(", ")) + Colors::ENDC());

    qDebug() << "Parsing Header Files for Type Definitions...";
    typeTracker.parseHeaderFiles();
    qDebug() << "Header Files parsed successfully.";

    runTests();
    return 0;
}

Verification::TypeDefinitionTracker::TypeDefinitionTracker() : isKernelMode(false) {
    externalTypes << "SYSTEM_INFORMATION_CLASS" << "TRANSACTIONMANAGER_INFORMATION_CLASS" << "RESOURCEMANAGER_INFORMATION_CLASS"
        << "ENLISTMENT_INFORMATION_CLASS" << "PFILE_SEGMENT_ELEMENT" << "EXECUTION_STATE" << "JOBOBJECTINFOCLASS"
        << "PSE_SIGNING_LEVEL" << "SE_SIGNING_LEVEL" << "PEXCEPTION_RECORD" << "PJOB_SET_ARRAY" << "PENCLAVE_ROUTINE"
        << "NOTIFICATION_MASK" << "volatile LONG *" << "PIO_STATUS_BLOCK" << "POBJECT_ATTRIBUTES" << "PUNICODE_STRING"
        << "SYSTEM_POWER_STATE" << "POWER_ACTION" << "PSECURITY_DESCRIPTOR" << "TOKEN_INFORMATION_CLASS"
        << "TRANSACTION_INFORMATION_CLASS" << "THREADINFOCLASS" << "PROCESSINFOCLASS" << "KEY_SET_INFORMATION_CLASS"
        << "OBJECT_INFORMATION_CLASS" << "FILE_INFORMATION_CLASS" << "LANGID" << "PCONTEXT" << "PSID"
        << "PSECURITY_QUALITY_OF_SERVICE" << "PKEY_VALUE_ENTRY" << "PPRIVILEGE_SET" << "POWER_INFORMATION_LEVEL"
        << "CLIENT_ID *" << "PMEM_EXTENDED_PARAMETER" << "PTRANSACTION_NOTIFICATION" << "PDEVICE_POWER_STATE"
        << "PPROCESSOR_NUMBER" << "OBJECT_ATTRIBUTES" << "PTOKEN_GROUPS" << "PTOKEN_PRIVILEGES" << "KTMOBJECT_TYPE"
        << "PKTMOBJECT_CURSOR" << "TOKEN_TYPE" << "PRTL_USER_PROCESS_PARAMETERS" << "PTOKEN_USER" << "PTOKEN_OWNER"
        << "PTOKEN_PRIMARY_GROUP" << "PTOKEN_DEFAULT_DACL" << "PTOKEN_SOURCE" << "PLUID" << "PGROUP_AFFINITY"
        << "PSID_AND_ATTRIBUTES" << "PULARGE_INTEGER" << "PGENERIC_MAPPING" << "POBJECT_TYPE_LIST" << "AUDIT_EVENT_TYPE"
        << "PTOKEN_MANDATORY_POLICY" << "PCWNF_STATE_NAME" << "PCWNF_TYPE_ID" << "WAIT_TYPE" << "PIO_APC_ROUTINE";
}

void Verification::TypeDefinitionTracker::parseHeaderFiles()
{
    QSettings settings(PathUtils::getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    isKernelMode = (syscallMode == "Zw");

    QString basePath = PathUtils::getProjectRoot();
    QMap<QString, QString> headerFiles;

    if (isKernelMode)
    {
        headerFiles["constants"] = basePath + "/SysCallerK/Wrapper/include/SysK/SysKConstants.h";
        headerFiles["types"] = basePath + "/SysCallerK/Wrapper/include/SysK/SysKTypes.h";
        headerFiles["externals"] = basePath + "/SysCallerK/Wrapper/include/SysK/SysKExternals.h";
    }
    else
    {
        headerFiles["constants"] = basePath + "/SysCaller/Wrapper/include/Sys/SysConstants.h";
        headerFiles["types"] = basePath + "/SysCaller/Wrapper/include/Sys/SysTypes.h";
        headerFiles["externals"] = basePath + "/SysCaller/Wrapper/include/Sys/SysExternals.h";
    }

    for (auto it = headerFiles.begin(); it != headerFiles.end(); ++it)
    {
        QString fileType = it.key();
        QString filepath = it.value();

        QFile file(filepath);

        if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            qWarning() << "Failed to open Header File:" << filepath;
            continue;
        }

        QString content = QTextStream(&file).readAll();
        file.close();

        if (fileType == "constants")
        {
            QRegularExpression defineRegex(R"(#define\s+(\w+)\s+(.+))");
            QRegularExpressionMatchIterator matches = defineRegex.globalMatch(content);

            while (matches.hasNext())
            {
                QRegularExpressionMatch match = matches.next();
                QString name = match.captured(1);
                QString value = match.captured(2);

                TypeDefinition def;
                def.file = QString("SysConstants%1.h").arg(isKernelMode ? "_k" : "");
                def.definition = QString("#define %1 %2").arg(name).arg(value);
                typeDefinitions.insert(name, def);
            }
        }
        /* parse comma types */
        QRegularExpression commaRegex(R"(}\s*(\w+),\s*\*\s*(\w+);)");
        QRegularExpressionMatchIterator commaMatches = commaRegex.globalMatch(content);

        while (commaMatches.hasNext())
        {
            QRegularExpressionMatch match = commaMatches.next();
            QString baseType = match.captured(1);
            QString ptrType = match.captured(2);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def1;
            def1.file = fileName;
            def1.definition = QString("typedef struct %1").arg(baseType);
            typeDefinitions.insert(baseType, def1);

            TypeDefinition def2;
            def2.file = fileName;
            def2.definition = QString("typedef %1* %2").arg(baseType).arg(ptrType);
            typeDefinitions.insert(ptrType, def2);
        }
        /* parse pointer types */
        QRegularExpression ptrRegex(R"(typedef\s+(?:struct\s+)?(?:_)?(\w+)\s*\*\s*(\w+);)");
        QRegularExpressionMatchIterator ptrMatches = ptrRegex.globalMatch(content);

        while (ptrMatches.hasNext())
        {
            QRegularExpressionMatch match = ptrMatches.next();
            QString baseType = match.captured(1);
            QString ptrType = match.captured(2);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def;
            def.file = fileName;
            def.definition = QString("typedef %1* %2").arg(baseType).arg(ptrType);
            typeDefinitions.insert(ptrType, def);
        }
        /* parse basic types */
        QRegularExpression basicRegex(R"(typedef\s+(?:struct\s+)?(?:_)?(\w+)\s+(\w+);)");
        QRegularExpressionMatchIterator basicMatches = basicRegex.globalMatch(content);

        while (basicMatches.hasNext())
        {
            QRegularExpressionMatch match = basicMatches.next();
            QString baseType = match.captured(1);
            QString newType = match.captured(2);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def;
            def.file = fileName;
            def.definition = QString("typedef %1 %2").arg(baseType).arg(newType);
            typeDefinitions.insert(newType, def);
        }
        /* parse structs */
        QRegularExpression structRegex(R"(typedef\s+struct\s+(?:_)?(\w+)\s*\{[^}]+\}\s*(\w+)\s*,\s*\*\s*(\w+);)");
        QRegularExpressionMatchIterator structMatches = structRegex.globalMatch(content);

        while (structMatches.hasNext())
        {
            QRegularExpressionMatch match = structMatches.next();
            QString structName = match.captured(2);
            QString ptrName = match.captured(3);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def1;
            def1.file = fileName;
            def1.definition = match.captured(0);
            typeDefinitions.insert(structName, def1);

            TypeDefinition def2;
            def2.file = fileName;
            def2.definition = QString("typedef %1* %2").arg(structName).arg(ptrName);
            typeDefinitions.insert(ptrName, def2);
        }
        /* parse enums */
        QRegularExpression enumRegex(R"(typedef\s+enum\s+(?:_)?(\w+)\s*\{[^}]+\}\s*(\w+);)");
        QRegularExpressionMatchIterator enumMatches = enumRegex.globalMatch(content);

        while (enumMatches.hasNext())
        {
            QRegularExpressionMatch match = enumMatches.next();
            QString enumName = match.captured(2);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def;
            def.file = fileName;
            def.definition = match.captured(0);
            typeDefinitions.insert(enumName, def);
        }
        /* parse function pointers */
        QRegularExpression funcPtrRegex(R"(typedef\s+\w+\s*\(\s*\w+\s*\*\s*(\w+)\s*\)\s*\([^)]*\))");
        QRegularExpressionMatchIterator funcPtrMatches = funcPtrRegex.globalMatch(content);

        while (funcPtrMatches.hasNext())
        {
            QRegularExpressionMatch match = funcPtrMatches.next();
            QString typeName = match.captured(1);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def;
            def.file = fileName;
            def.definition = QString("typedef function_ptr %1").arg(typeName);
            typeDefinitions.insert(typeName, def);
        }
        /* parse const pointer types */
        QRegularExpression constPtrRegex(R"(typedef\s+const\s+(\w+)\s*\*\s*(\w+);)");
        QRegularExpressionMatchIterator constPtrMatches = constPtrRegex.globalMatch(content);

        while (constPtrMatches.hasNext())
        {
            QRegularExpressionMatch match = constPtrMatches.next();
            QString baseType = match.captured(1);
            QString newType = match.captured(2);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def;
            def.file = fileName;
            def.definition = QString("typedef const %1* %2").arg(baseType).arg(newType);
            typeDefinitions.insert(newType, def);
        }
        /* parse WNF types */
        QRegularExpression wnfRegex(R"(typedef\s+(?:const\s+)?(?:struct\s+)?_?(\w+)\s*(?:\*\s*)?(\w+)(?:\s*,\s*\*\s*(\w+))?;)");
        QRegularExpressionMatchIterator wnfMatches = wnfRegex.globalMatch(content);

        while (wnfMatches.hasNext())
        {
            QRegularExpressionMatch match = wnfMatches.next();
            QString baseType = match.captured(1);
            QString newType = match.captured(2);
            QString ptrType = match.captured(3);
            QString fileName = QString("Sys%1%2.h").arg(fileType.at(0).toUpper() + fileType.mid(1))
                                     .arg(isKernelMode ? "_k" : "");

            TypeDefinition def1;
            def1.file = fileName;
            def1.definition = QString("typedef %1 %2").arg(baseType).arg(newType);
            typeDefinitions.insert(newType, def1);

            if (!ptrType.isEmpty())
            {
                TypeDefinition def2;
                def2.file = fileName;
                def2.definition = QString("typedef %1* %2").arg(newType).arg(ptrType);
                typeDefinitions.insert(ptrType, def2);
            }
        }

        QStringList commonTypes =
        {
            "HANDLE", "PVOID", "BOOLEAN", "ULONG", "PULONG", "ACCESS_MASK",
            "PHANDLE", "PACCESS_MASK", "PBOOLEAN", "VOID",
            "ULONG_PTR", "PULONG_PTR", "ULONG64", "PULONG64",
            "UCHAR", "PUCHAR"
        };

        for (const QString& typeName : commonTypes)
        {
            TypeDefinition def;
            def.file = QString("SysTypes%1.h").arg(isKernelMode ? "_k" : "");
            def.definition = QString("typedef base %1").arg(typeName);
            typeDefinitions.insert(typeName, def);
        }
    }

    if (!typeDefinitions.contains("WNF_CHANGE_STAMP"))
    {
        TypeDefinition def;
        def.file = QString("SysExternals%1.h").arg(isKernelMode ? "_k" : "");
        def.definition = "typedef ULONG WNF_CHANGE_STAMP";
        typeDefinitions.insert("WNF_CHANGE_STAMP", def);
    }

    if (!typeDefinitions.contains("PCWNF_STATE_NAME"))
    {
        TypeDefinition def;
        def.file = QString("SysExternals%1.h").arg(isKernelMode ? "_k" : "");
        def.definition = "typedef WNF_STATE_NAME* PCWNF_STATE_NAME";
        typeDefinitions.insert("PCWNF_STATE_NAME", def);
    }

    if (!typeDefinitions.contains("PCWNF_TYPE_ID"))
    {
        TypeDefinition def;
        def.file = QString("SysExternals%1.h").arg(isKernelMode ? "_k" : "");
        def.definition = "typedef WNF_TYPE_ID* PCWNF_TYPE_ID";
        typeDefinitions.insert("PCWNF_TYPE_ID", def);
    }

    if (!typeDefinitions.contains("WAIT_TYPE"))
    {
        TypeDefinition def;
        def.file = QString("SysExternals%1.h").arg(isKernelMode ? "_k" : "");
        def.definition = "typedef enum WAIT_TYPE";
        typeDefinitions.insert("WAIT_TYPE", def);
    }

    if (!typeDefinitions.contains("PIO_APC_ROUTINE"))
    {
        TypeDefinition def;
        def.file = QString("SysTypes%1.h").arg(isKernelMode ? "_k" : "");
        def.definition = "typedef function_ptr PIO_APC_ROUTINE";
        typeDefinitions.insert("PIO_APC_ROUTINE", def);
    }
}

std::optional<Verification::TypeDefinition> Verification::TypeDefinitionTracker::checkType(const QString& typeName, bool isKernelMode)
{
    QString cleanTypeName = typeName.trimmed();

    if (externalTypes.contains(cleanTypeName))
    {
        TypeDefinition def;
        def.file = isKernelMode ? "Windows WDK" : "Windows SDK";
        def.definition = QString("typedef external %1").arg(cleanTypeName);
        return def;
    }

    if (cleanTypeName.startsWith("const "))
    {
        cleanTypeName = cleanTypeName.mid(6);
    }

    if (cleanTypeName.contains(" *"))
    {
        cleanTypeName = cleanTypeName.replace(" *", "*");
        QString baseType = cleanTypeName.left(cleanTypeName.length() - 1);
        QString ptrType = "P" + baseType;

        if (typeDefinitions.contains(ptrType))
        {
            return typeDefinitions[ptrType];
        }

        if (typeDefinitions.contains(cleanTypeName))
        {
            return typeDefinitions[cleanTypeName];
        }
    }
    QStringList basicTypes = {
        "LONG", "ULONG", "INT", "UINT", "CHAR", "WCHAR", "BOOL", "BOOLEAN",
        "SHORT", "USHORT", "LONGLONG", "ULONGLONG", "BYTE", "WORD", "DWORD",
        "VOID", "PVOID", "HANDLE", "SIZE_T", "NTSTATUS",
        "ULONG_PTR", "LONG", "PLONG", "PULONG_PTR", "ULONG64", "PULONG64",
        "UCHAR", "PUCHAR", "PCHAR", "PUSHORT", "PCSTR", "PWSTR", "PCWSTR", "PCWCHAR",
        "LARGE_INTEGER", "ULARGE_INTEGER", "KPRIORITY", "PDEVICE_OBJECT", "PEPROCESS",
        "PETHREAD", "PSECTION_OBJECT", "PLPC_MESSAGE", "PFILE_OBJECT", "PKEVENT", "PDRIVER_OBJECT",
        "PKTHREAD", "PMDL", "PPS_APC_ROUTINE", "PRTL_USER_PROCESS_PARAMETERS", "PCONTEXT",
        "SE_SIGNING_LEVEL", "LPCGUID", "LPGUID", "EVENT_TYPE", "NOTIFICATION_MASK",
        "KPROFILE_SOURCE", "TIMER_TYPE", "PJOB_SET_ARRAY", "POBJECT_BOUNDARY_DESCRIPTOR",
        "KAFFINITY", "PGROUP_AFFINITY", "PINITIAL_TEB", "PUSER_THREAD_START_ROUTINE",
        "PPS_ATTRIBUTE_LIST", "PPS_CREATE_INFO", "TOKEN_TYPE", "PTOKEN_USER", "PTOKEN_OWNER",
        "PTOKEN_PRIMARY_GROUP", "PTOKEN_DEFAULT_DACL", "PTOKEN_SOURCE", "PTOKEN_MANDATORY_POLICY",
        "PWNF_STATE_NAME", "PCWNF_STATE_NAME", "WNF_STATE_NAME_LIFETIME", "WNF_DATA_SCOPE",
        "PCWNF_TYPE_ID", "PIO_APC_ROUTINE", "PCGUID", "PGUID", "PTOKEN_GROUPS_AND_PRIVILEGES",
        "PSECURITY_DESCRIPTOR_RELATIVE", "PSID_AND_ATTRIBUTES_HASH", "PTOKEN_AUDIT_POLICY",
        "PTOKEN_PRIVILEGES_AND_GROUPS", "SECURITY_CONTEXT_TRACKING_MODE",
        "SECURITY_QUALITY_OF_SERVICE_FLAGS", "SECURITY_IMPERSONATION_LEVEL",
        "PTOKEN_ACCESS_INFORMATION", "PTOKEN_AUDIT_POLICY_INFORMATION", "KEY_INFORMATION_CLASS",
        "KEY_VALUE_INFORMATION_CLASS", "KTMOBJECT_TYPE", "PKTMOBJECT_CURSOR",
        "FILTER_BOOT_OPTION_OPERATION", "LANGID", "PLCID", "PWNF_DELIVERY_DESCRIPTOR",
        "PPROCESSOR_NUMBER", "DWORD", "PDEVICE_POWER_STATE", "POWER_ACTION", "SYSTEM_POWER_STATE",
        "PTRANSACTION_NOTIFICATION", "PCM_EXTENDED_PARAMETER", "PARTITION_INFORMATION_CLASS",
        "DIRECTORY_NOTIFY_INFORMATION_CLASS", "IO_SESSION_EVENT", "IO_SESSION_STATE",
        "OBJECT_ATTRIBUTES", "ULONG", "ULONG_PTR", "UINT32", "UINT64", "PDEVICE_POWER_STATE_CONTEXT",
        "PPOWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES", "PPOWER_SESSION_RIT_STATE", "PSYSTEM_POWER_POLICY",
        "PDEVICE_NOTIFY_SUBSCRIBE_PARAMETERS", "PFILE_NOTIFY_INFORMATION", "PKEY_VALUE_ENTRY",
        "PKEY_NAME_INFORMATION", "PKEY_CACHED_INFORMATION", "PKEY_VIRTUALIZATION_INFORMATION",
        "PKEY_WRITE_TIME_INFORMATION", "PLUGPLAY_CONTROL_CLASS", "POWER_INFORMATION_LEVEL",
        "PNTPSS_MEMORY_BULK_INFORMATION", "MEMORY_INFORMATION_CLASS", "PFILE_BASIC_INFORMATION",
        "PBOOT_OPTIONS", "FILE_INFORMATION_CLASS", "FSINFOCLASS", "SYSK_FSINFOCLASS",
        "PFILE_SEGMENT_ELEMENT", "EVENT_INFORMATION_CLASS", "ATOM_INFORMATION_CLASS",
        "ENLISTMENT_INFORMATION_CLASS", "PORT_INFORMATION_CLASS", "RESOURCEMANAGER_INFORMATION_CLASS",
        "TOKEN_INFORMATION_CLASS", "TRANSACTION_INFORMATION_CLASS", "TRANSACTIONMANAGER_INFORMATION_CLASS",
        "WORKERFACTORYINFOCLASS", "IO_COMPLETION_INFORMATION_CLASS", "MUTANT_INFORMATION_CLASS",
        "OBJECT_INFORMATION_CLASS", "SECTION_INFORMATION_CLASS", "SEMAPHORE_INFORMATION_CLASS",
        "TIMER_INFORMATION_CLASS", "PCUNICODE_STRING", "SECURE_SETTING_VALUE_TYPE", "PWNF_CHANGE_STAMP",
        "WNF_STATE_NAME_INFORMATION", "PEXCEPTION_RECORD", "PCRM_PROTOCOL_ID", "PFILE_IO_COMPLETION_INFORMATION",
        "PFILE_INFORMATION", "PSECURITY_POLICY_INFORMATION", "PPROCESS_INFORMATION", "PTOKEN_INFORMATION",
        "PMUTANT_INFORMATION", "PSEMAPHORE_INFORMATION", "PTIMER_INFORMATION", "PPORT_INFORMATION",
        "PRESOURCEMANAGER_INFORMATION", "PTRANSACTION_INFORMATION", "PTRANSACTIONMANAGER_INFORMATION",
        "PWORKER_FACTORY_INFORMATION", "PIO_COMPLETION_INFORMATION", "PSECTION_INFORMATION",
        "POBJECT_INFORMATION", "PVOLUME_INFORMATION", "PWNF_STATE_INFORMATION", "PEXCEPTION_INFORMATION",
        "PPROTOCOL_INFORMATION", "SE_SET_FILE_CACHE_INFORMATION", "SE_SET_FILE_CACHE_INFORMATION *",
        "LCID", "KEY_SET_INFORMATION_CLASS", "SYMBOLIC_LINK_INFO_CLASS", "PMEMORY_RANGE_ENTRY",
        "EXECUTION_STATE", "EXECUTION_STATE *", "PTIMER_APC_ROUTINE", "PT2_SET_PARAMETERS",
        "TIMER_SET_INFORMATION_CLASS", "SHUTDOWN_ACTION", "SYSDBG_COMMAND", "ETWTRACECONTROLCODE",
        "PFILE_PATH", "WNF_CHANGE_STAMP", "LOGICAL", "VDMSERVICECLASS", "PDBGUI_WAIT_STATE_CHANGE",
        "WAIT_TYPE", "PWORKER_FACTORY_DEFERRED_WORK", "PSE_SET_FILE_CACHE_INFORMATION", "PEXECUTION_STATE",
        "PTIMER_SET_INFORMATION", "PSHUTDOWN_ACTION", "PSYSDBG_COMMAND", "PETWTRACECONTROLCODE",
        "PVDMSERVICECLASS", "PWORKER_FACTORY_INFORMATION", "PDBGUI_WAIT_STATE_CHANGE", "PWAIT_TYPE",
        "PLOGICAL", "PFILE_PATH_INFORMATION", "PFILE_NETWORK_OPEN_INFORMATION"
    };
    if (basicTypes.contains(cleanTypeName)) {
        TypeDefinition def;
        def.file = QString("SysTypes%1.h").arg(isKernelMode ? "_k" : "");
        def.definition = QString("typedef base %1").arg(cleanTypeName);
        return def;
    }
    if (cleanTypeName.endsWith("*")) {
        QString baseType = cleanTypeName.left(cleanTypeName.length() - 1).trimmed();
        if (typeDefinitions.contains(baseType)) {
            return typeDefinitions[baseType];
        }
        QString ptrType = "P" + baseType;
        if (typeDefinitions.contains(ptrType)) {
            return typeDefinitions[ptrType];
        }
    }
    if (cleanTypeName.startsWith("P")) {
        QString baseType = cleanTypeName.mid(1);
        if (typeDefinitions.contains(baseType)) {
            return typeDefinitions[baseType];
        }
    }
    if (typeDefinitions.contains(cleanTypeName)) {
        return typeDefinitions[cleanTypeName];
    }
    return std::nullopt;
}

void Verification::parseSyscallDefinitions()
{
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");
    QString syscallPrefix = (syscallMode == "Nt") ? "Sys" : "SysK";

    QString headerPath = getHeaderFilePath(isKernelMode);
    QString asmPath = getAsmFilePath(isKernelMode);

    qDebug() << QString("Parsing Syscall Definitions from: %1").arg(headerPath);

    QFile file(headerPath);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qWarning() << "Failed to open Header File:" << headerPath;
        outputProgress(Colors::FAIL() + QString("Failed to open Header File: %1").arg(headerPath) + Colors::ENDC());
        return;
    }

    QString content = QTextStream(&file).readAll();
    file.close();

    QRegularExpression externCRegex(R"(#ifdef\s+__cplusplus\s+extern\s+"C"\s+\{)");
    bool hasExternC = externCRegex.match(content).hasMatch();

    QString pattern1 = QString(R"(extern\s*"C"\s*((?:NTSTATUS|ULONG|BOOLEAN|VOID))\s+((?:SC|%1)\w+)\s*\(([\s\S]*?)\)\s*;)").arg(syscallPrefix);
    QString pattern2 = QString(R"(((?:NTSTATUS|ULONG|BOOLEAN|VOID))\s+((?:SC|%1)\w+)\s*\(([\s\S]*?)\)\s*;)").arg(syscallPrefix);

    QRegularExpression regex1(pattern1);
    QRegularExpression regex2(pattern2);

    QRegularExpressionMatchIterator matches = regex1.globalMatch(content);
    QList<QRegularExpressionMatch> matchesList;

    while (matches.hasNext())
    {
        matchesList.append(matches.next());
    }

    if (matchesList.isEmpty() || hasExternC)
    {
        matches = regex2.globalMatch(content);
        matchesList.clear();

        while (matches.hasNext())
        {
            matchesList.append(matches.next());
        }
    }

    qDebug() << QString("Parsing Syscall Offsets from: %1").arg(asmPath);
    QMap<QString, QString> offsets = parseSyscallOffsets(asmPath);
    qDebug() << QString("Found %1 Syscall Definitions").arg(matchesList.size());

    for (const QRegularExpressionMatch& match : matchesList)
    {
        QString returnType = match.captured(1);
        QString name = match.captured(2);

        if (name.startsWith("SC"))
        {
            name = syscallPrefix + name.mid(2);
        }

        QString paramsStr = match.captured(3).trimmed();
        QList<Parameter> params;

        if (!paramsStr.isEmpty() && paramsStr.toUpper() != "VOID")
        {
            QStringList paramList = paramsStr.split(',');

            for (const QString& param : paramList)
            {
                QString cleanParam = param.trimmed();
                int commentPos = cleanParam.indexOf("//");

                if (commentPos != -1)
                {
                    cleanParam = cleanParam.left(commentPos);
                }

                commentPos = cleanParam.indexOf("/*");

                if (commentPos != -1)
                {
                    cleanParam = cleanParam.left(commentPos);
                }

                cleanParam = cleanParam.trimmed();

                if (cleanParam.isEmpty()) continue;

                bool isOptional = cleanParam.contains("OPTIONAL");
                QString paramType = cleanParam.replace("OPTIONAL", "").trimmed();

                if (!paramType.isEmpty())
                {
                    QStringList paramParts = paramType.split(' ', Qt::SkipEmptyParts);

                    if (!paramParts.isEmpty())
                    {
                        QString paramName = paramParts.last();
                        paramType = paramParts.mid(0, paramParts.size() - 1).join(' ');
                        commentPos = paramType.indexOf("//");

                        if (commentPos != -1)
                        {
                            paramType = paramType.left(commentPos);
                        }

                        commentPos = paramType.indexOf("/*");

                        if (commentPos != -1)
                        {
                            paramType = paramType.left(commentPos);
                        }

                        paramType = paramType.trimmed();

                        if (!paramType.isEmpty())
                        {
                            params.append({paramType, paramName, isOptional});
                        }
                    }
                }
            }
        }

        QString offset = offsets.value(name, "Unknown");
        SyscallDefinition def;
        def.name = name;
        def.returnType = returnType;
        def.parameters = params;
        def.offset = offset;
        def.description = "";
        syscalls[name] = def;
    }

    qDebug() << QString("Successfully parsed %1 Syscall Definitions").arg(syscalls.size());
}

QMap<QString, QString> Verification::parseSyscallOffsets(const QString& asmPath)
{
    QMap<QString, QString> offsets;
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    QString syscallPrefix = (syscallMode == "Nt") ? "Sys" : "SysK";

    QFile file(asmPath);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qWarning() << "Failed to open ASM File:" << asmPath;
        outputProgress(Colors::FAIL() + QString("Failed to open ASM File: %1").arg(asmPath) + Colors::ENDC());
        return offsets;
    }

    QString content = QTextStream(&file).readAll();
    file.close();

    QString pattern = QString(R"(((?:SC|Sys|SysK)\w+)\s+PROC[\s\S]*?mov\s+eax,\s+([\dA-Fa-fh]+))");
    QRegularExpression regex(pattern);
    QRegularExpressionMatchIterator matches = regex.globalMatch(content);
    int offsetCount = 0;

    while (matches.hasNext())
    {
        QRegularExpressionMatch match = matches.next();
        QString name = match.captured(1);
        QString offset = match.captured(2);

        if (name.startsWith("SC"))
        {
            name = syscallPrefix + name.mid(2);
        }

        offsets[name] = offset;
        offsetCount++;
    }

    outputProgress(QString("Found %1 Syscall Offsets in ASM File").arg(offsetCount));
    return offsets;
}

std::optional<int> Verification::getOffsetFromDll(const QString& syscallName, const QString& dllPath)
{
    QString dllPathToUse = dllPath.isEmpty() ? this->dllPath : dllPath;

    qDebug() << QString("Getting Offset for %1 from DLL: %2").arg(syscallName).arg(dllPathToUse);

    QByteArray dllPathBytes = dllPathToUse.toLocal8Bit();
    const char* dllPathCStr = dllPathBytes.constData();

    pe = peparse::ParsePEFromFile(dllPathCStr);

    if (!pe)
    {
        qWarning() << "Failed to parse PE File:" << dllPathToUse;
        return std::nullopt;
    }

    imageBase = pe->peHeader.nt.OptionalHeader64.ImageBase;
    QString primaryName, secondaryName;

    if (syscallName.startsWith("SysK"))
    {
        primaryName = "Nt" + syscallName.mid(4);
        secondaryName = "Zw" + syscallName.mid(4);
    }
    else if (syscallName.startsWith("Sys"))
    {
        primaryName = "Nt" + syscallName.mid(3);
        secondaryName = "Zw" + syscallName.mid(3);
    }
    else
    {
        primaryName = syscallName;
        secondaryName = syscallName;
    }

    std::optional<int> result = std::nullopt;
    syscallNumbers.clear();

    peparse::IterExpVA(pe, [](void* N, const peparse::VA& addr, const std::string& mod, const std::string& fn) -> int
    {
        auto* verification = static_cast<Verification*>(N);

        /* safety check for the callback parameters */
        if (!verification || fn.empty())
        {
            return 0;
        }

        /* use a safer string conversion */
        QString funcName;

        try
        {
            funcName = QString::fromUtf8(fn.c_str(), static_cast<int>(fn.length()));
        }
        catch (...)
        {
            return 0;
        }

        if (!funcName.startsWith("Nt") && !funcName.startsWith("Zw"))
        {
            return 0;
        }

        /* get function RVA (addr is VA, subtract image base to get RVA) */
        uint32_t funcRVA = static_cast<uint32_t>(addr - verification->imageBase);
        uint32_t fileOffset = 0;

        /* safety check for RVA calculation */
        if (addr < verification->imageBase)
        {
            return 0;
        }

        if (SyscallExtractor::rvaToFileOffset(verification->pe, funcRVA, fileOffset))
        {
            if (!verification->pe || !verification->pe->fileBuffer)
            {
                return 0;
            }

            std::vector<uint8_t> funcBytes;
            size_t bytesRead = SyscallExtractor::readBytesFromBuffer(verification->pe->fileBuffer, fileOffset, 32, funcBytes);

            if (bytesRead > 0)
            {
                if (bytesRead >= 8)
                {
                    for (size_t i = 0; i <= bytesRead - 8; ++i)
                    {
                        if (funcBytes[i] == 0x4c && funcBytes[i+1] == 0x8b && funcBytes[i+2] == 0xd1)
                        {
                            if (funcBytes[i+3] == 0xb8)
                            {
                                uint32_t syscallId = funcBytes[i+4] |
                                                   (funcBytes[i+5] << 8) |
                                                   (funcBytes[i+6] << 16) |
                                                   (funcBytes[i+7] << 24);

                                if (syscallId <= 0xFFFF)
                                {
                                    verification->syscallNumbers[funcName] = static_cast<int>(syscallId);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        return 0;
    }, this);

    if (syscallNumbers.contains(primaryName))
    {
        result = syscallNumbers[primaryName];
    }
    else if (syscallNumbers.contains(secondaryName))
    {
        result = syscallNumbers[secondaryName];
    }

    peparse::DestructParsedPE(pe);
    return result;
}

Verification::TestResult Verification::testSyscall(const SyscallDefinition& syscall)
{
    QSettings settings(getIniPath(), QSettings::IniFormat);
    QString syscallMode = settings.value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");

    TestResult result;
    result.name = syscall.name;
    result.status = "SUCCESS";
    result.offset = syscall.offset;
    result.returnType = syscall.returnType;
    result.parameterCount = syscall.parameters.size();

    QRegularExpression versionRegex(R"((?:Sys|SysK)(\w+?)(\d+)?$)");
    QRegularExpressionMatch versionMatch = versionRegex.match(syscall.name);
    QString dllPathToUse = dllPath;

    if (versionMatch.hasMatch() && !versionMatch.captured(2).isEmpty())
    {
        int version = versionMatch.captured(2).toInt();

        if (version > 1 && dllPaths.size() >= version)
        {
            dllPathToUse = dllPaths[version - 1];
        }
    }

    /* validate return type */
    QStringList validReturnTypes = {"NTSTATUS", "BOOL", "HANDLE", "VOID", "ULONG", "ULONG_PTR", "UINT32", "UINT64"};

    if (!validReturnTypes.contains(syscall.returnType))
    {
        result.errors.append(QString("Unexpected return type: %1").arg(syscall.returnType));
    }

    /* validate parameters */
    for (const Parameter& param : syscall.parameters)
    {
        if (!validateParameterType(param.type))
        {
            result.errors.append(QString("Invalid Parameter Type: %1").arg(param.type));
        }
    }

    /* validate offset */
    QString offset = syscall.offset.toLower().replace("h", "");
    bool ok;
    int offsetValue = offset.toInt(&ok, 16);

    if (ok)
    {
        if (offsetValue > 0x0200)
        {
            result.errors.append(QString("Suspicious Syscall Offset: 0x%1 (expected range: 0x0000-0x0200)").arg(offset));
        }

        std::optional<int> expectedOffset = getOffsetFromDll(syscall.name, dllPathToUse);

        if (expectedOffset.has_value() && expectedOffset.value() != offsetValue)
        {
            result.errors.append(QString("Offset Mismatch: Got 0x%1, Expected 0x%2")
                               .arg(offset)
                               .arg(QString::number(expectedOffset.value(), 16).toUpper()));
        }
    }
    else
    {
        result.errors.append(QString("Invalid Syscall Offset Format: %1").arg(syscall.offset));
    }

    /* check type definitions */
    for (const Parameter& param : syscall.parameters)
    {
        std::optional<TypeDefinition> typeInfo = typeTracker.checkType(param.type, isKernelMode);

        if (!typeInfo.has_value())
        {
            result.errors.append(QString("Type '%1' not found in Header Files").arg(param.type));
        }
        else
        {
            result.typeDefinitions.append({param.type, typeInfo.value().file});
        }
    }

    if (!result.errors.isEmpty())
    {
        result.status = "FAILED";
    }

    return result;
}

bool Verification::validateParameterType(const QString& paramType)
{
    QString cleanParamType = paramType.trimmed();

    if (cleanParamType.isEmpty())
    {
        return false;
    }

    if (cleanParamType.startsWith("const "))
    {
        cleanParamType = cleanParamType.mid(6);
    }

    QStringList validTypes =
    {
        "HANDLE", "PHANDLE", "PVOID", "ULONG", "PULONG", "BOOLEAN",
        "POBJECT_ATTRIBUTES", "ACCESS_MASK", "PCLIENT_ID", "PLARGE_INTEGER",
        "PPORT_MESSAGE", "PPORT_VIEW", "PREMOTE_PORT_VIEW",
        "PSECURITY_DESCRIPTOR", "PGENERIC_MAPPING", "PPRIVILEGE_SET",
        "PNTSTATUS", "PSID", "PUNICODE_STRING", "POBJECT_TYPE_LIST",
        "AUDIT_EVENT_TYPE", "PLUID", "PACCESS_MASK", "PBOOLEAN", "USHORT", "UCHAR",
        "PCWSTR", "PRTL_ATOM", "PROCESS_ACTIVITY_TYPE", "PMEM_EXTENDED_PARAMETER",
        "PSIZE_T", "SIZE_T", "PALPC_PORT_ATTRIBUTES", "PALPC_MESSAGE_ATTRIBUTES",
        "PALPC_CONTEXT_ATTR", "PALPC_DATA_VIEW_ATTR", "PALPC_SECURITY_ATTR", "PALPC_HANDLE",
        "PVOID*", "PHANDLE*", "PULONG*", "PULONG_PTR", "PIO_STATUS_BLOCK", "PFILE_INFORMATION_CLASS",
        "PSID_AND_ATTRIBUTES", "PTOKEN_PRIVILEGES", "PTOKEN_GROUPS", "PSECURITY_QUALITY_OF_SERVICE",
        "SECURITY_INFORMATION", "SYSTEM_INFORMATION_CLASS", "THREADINFOCLASS", "PROCESSINFOCLASS",
        "JOBOBJECTINFOCLASS", "DEBUGOBJECTINFOCLASS", "PBOOT_ENTRY", "PEFI_DRIVER_ENTRY",
        "PTOKEN_SECURITY_ATTRIBUTES_INFORMATION", "PCOBJECT_ATTRIBUTES", "MEMORY_RESERVE_TYPE",
        "PULARGE_INTEGER", "PCHAR", "ALPC_PORT_INFORMATION_CLASS", "ALPC_MESSAGE_INFORMATION_CLASS",
        "PROCESS_STATE_CHANGE_TYPE", "THREAD_STATE_CHANGE_TYPE", "PENCLAVE_ROUTINE",
        "PT2_CANCEL_PARAMETERS", "NTSTATUS", "LONG", "PLONG", "PWSTR", "PCSTR", "PCWCHAR",
        "LARGE_INTEGER", "ULARGE_INTEGER", "KPRIORITY", "PDEVICE_OBJECT", "PEPROCESS",
        "PETHREAD", "PSECTION_OBJECT", "PLPC_MESSAGE", "PFILE_OBJECT", "PKEVENT", "PDRIVER_OBJECT",
        "PKTHREAD", "PMDL", "PPS_APC_ROUTINE", "PRTL_USER_PROCESS_PARAMETERS", "PCONTEXT",
        "SE_SIGNING_LEVEL", "LPCGUID", "LPGUID", "EVENT_TYPE", "NOTIFICATION_MASK",
        "KPROFILE_SOURCE", "TIMER_TYPE", "PJOB_SET_ARRAY", "POBJECT_BOUNDARY_DESCRIPTOR",
        "KAFFINITY", "PGROUP_AFFINITY", "PINITIAL_TEB", "PUSER_THREAD_START_ROUTINE",
        "PPS_ATTRIBUTE_LIST", "PPS_CREATE_INFO", "TOKEN_TYPE", "PTOKEN_USER", "PTOKEN_OWNER",
        "PTOKEN_PRIMARY_GROUP", "PTOKEN_DEFAULT_DACL", "PTOKEN_SOURCE", "PTOKEN_MANDATORY_POLICY",
        "PWNF_STATE_NAME", "PCWNF_STATE_NAME", "WNF_STATE_NAME_LIFETIME", "WNF_DATA_SCOPE",
        "PCWNF_TYPE_ID", "PIO_APC_ROUTINE", "PCGUID", "PGUID", "PTOKEN_GROUPS_AND_PRIVILEGES",
        "PSECURITY_DESCRIPTOR_RELATIVE", "PSID_AND_ATTRIBUTES_HASH", "PTOKEN_AUDIT_POLICY",
        "PTOKEN_PRIVILEGES_AND_GROUPS", "SECURITY_CONTEXT_TRACKING_MODE",
        "SECURITY_QUALITY_OF_SERVICE_FLAGS", "SECURITY_IMPERSONATION_LEVEL",
        "PTOKEN_ACCESS_INFORMATION", "PTOKEN_AUDIT_POLICY_INFORMATION", "KEY_INFORMATION_CLASS",
        "KEY_VALUE_INFORMATION_CLASS", "KTMOBJECT_TYPE", "PKTMOBJECT_CURSOR",
        "FILTER_BOOT_OPTION_OPERATION", "LANGID", "PLCID", "PWNF_DELIVERY_DESCRIPTOR",
        "PPROCESSOR_NUMBER", "DWORD", "PDEVICE_POWER_STATE", "POWER_ACTION", "SYSTEM_POWER_STATE",
        "PTRANSACTION_NOTIFICATION", "PCM_EXTENDED_PARAMETER", "PARTITION_INFORMATION_CLASS",
        "DIRECTORY_NOTIFY_INFORMATION_CLASS", "IO_SESSION_EVENT", "IO_SESSION_STATE",
        "OBJECT_ATTRIBUTES", "ULONG", "ULONG_PTR", "UINT32", "UINT64", "PDEVICE_POWER_STATE_CONTEXT",
        "PPOWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES", "PPOWER_SESSION_RIT_STATE", "PSYSTEM_POWER_POLICY",
        "PDEVICE_NOTIFY_SUBSCRIBE_PARAMETERS", "PFILE_NOTIFY_INFORMATION", "PKEY_VALUE_ENTRY",
        "PKEY_NAME_INFORMATION", "PKEY_CACHED_INFORMATION", "PKEY_VIRTUALIZATION_INFORMATION",
        "PKEY_WRITE_TIME_INFORMATION", "PLUGPLAY_CONTROL_CLASS", "POWER_INFORMATION_LEVEL",
        "PNTPSS_MEMORY_BULK_INFORMATION", "MEMORY_INFORMATION_CLASS", "PFILE_BASIC_INFORMATION",
        "PBOOT_OPTIONS", "FILE_INFORMATION_CLASS", "FSINFOCLASS", "SYSK_FSINFOCLASS",
        "PFILE_SEGMENT_ELEMENT", "EVENT_INFORMATION_CLASS", "ATOM_INFORMATION_CLASS",
        "ENLISTMENT_INFORMATION_CLASS", "PORT_INFORMATION_CLASS", "RESOURCEMANAGER_INFORMATION_CLASS",
        "TOKEN_INFORMATION_CLASS", "TRANSACTION_INFORMATION_CLASS", "TRANSACTIONMANAGER_INFORMATION_CLASS",
        "WORKERFACTORYINFOCLASS", "IO_COMPLETION_INFORMATION_CLASS", "MUTANT_INFORMATION_CLASS",
        "OBJECT_INFORMATION_CLASS", "SECTION_INFORMATION_CLASS", "SEMAPHORE_INFORMATION_CLASS",
        "TIMER_INFORMATION_CLASS", "PCUNICODE_STRING", "SECURE_SETTING_VALUE_TYPE",
        "PWNF_CHANGE_STAMP", "WNF_STATE_NAME_INFORMATION", "PEXCEPTION_RECORD", "PCRM_PROTOCOL_ID",
        "PFILE_IO_COMPLETION_INFORMATION", "PFILE_INFORMATION", "PSECURITY_POLICY_INFORMATION",
        "PPROCESS_INFORMATION", "PTOKEN_INFORMATION", "PMUTANT_INFORMATION", "PSEMAPHORE_INFORMATION",
        "PTIMER_INFORMATION", "PPORT_INFORMATION", "PRESOURCEMANAGER_INFORMATION", "PTRANSACTION_INFORMATION",
        "PTRANSACTIONMANAGER_INFORMATION", "PWORKER_FACTORY_INFORMATION", "PIO_COMPLETION_INFORMATION",
        "PSECTION_INFORMATION", "POBJECT_INFORMATION", "PVOLUME_INFORMATION", "PWNF_STATE_INFORMATION",
        "PEXCEPTION_INFORMATION", "PPROTOCOL_INFORMATION", "SE_SET_FILE_CACHE_INFORMATION",
        "SE_SET_FILE_CACHE_INFORMATION *", "LCID", "KEY_SET_INFORMATION_CLASS", "SYMBOLIC_LINK_INFO_CLASS",
        "PMEMORY_RANGE_ENTRY", "EXECUTION_STATE", "EXECUTION_STATE *", "PTIMER_APC_ROUTINE",
        "PT2_SET_PARAMETERS", "TIMER_SET_INFORMATION_CLASS", "SHUTDOWN_ACTION", "SYSDBG_COMMAND",
        "ETWTRACECONTROLCODE", "PFILE_PATH", "WNF_CHANGE_STAMP", "LOGICAL", "VDMSERVICECLASS",
        "PDBGUI_WAIT_STATE_CHANGE", "WAIT_TYPE", "PWORKER_FACTORY_DEFERRED_WORK",
        "PSE_SET_FILE_CACHE_INFORMATION", "PEXECUTION_STATE", "PTIMER_SET_INFORMATION",
        "PSHUTDOWN_ACTION", "PSYSDBG_COMMAND", "PETWTRACECONTROLCODE", "PVDMSERVICECLASS",
        "PWORKER_FACTORY_INFORMATION", "PDBGUI_WAIT_STATE_CHANGE", "PWAIT_TYPE", "PLOGICAL",
        "PFILE_PATH_INFORMATION", "PFILE_NETWORK_OPEN_INFORMATION"
    };

    if (cleanParamType.endsWith("*"))
    {
        QString baseType = cleanParamType.left(cleanParamType.length() - 1).trimmed();
        QString pointerType = "P" + baseType;

        return (validTypes.contains(baseType) || validTypes.contains(pointerType) ||
                std::any_of(validTypes.begin(), validTypes.end(), [&baseType](const QString& validType)
                {
                    return baseType.contains(validType);
                }));
    }

    if (cleanParamType.contains("["))
    {
        cleanParamType = cleanParamType.left(cleanParamType.indexOf("[")).trimmed();
    }

    if (cleanParamType.startsWith("LP"))
    {
        QString altType = "P" + cleanParamType.mid(2);

        return (validTypes.contains(cleanParamType) || validTypes.contains(altType) ||
                std::any_of(validTypes.begin(), validTypes.end(), [&cleanParamType](const QString& validType)
                {
                    return cleanParamType.contains(validType);
                }));
    }

    return (validTypes.contains(cleanParamType) ||
            std::any_of(validTypes.begin(), validTypes.end(), [&cleanParamType](const QString& validType)
            {
                return cleanParamType.contains(validType);
            }));
}

void Verification::runTests(const QString& outputFormat)
{
    parseSyscallDefinitions();
    outputProgress(Colors::BOLD() + QString("Testing %1 Syscalls...").arg(syscalls.size()) + Colors::ENDC());
    outputProgress("");

    for (auto it = syscalls.begin(); it != syscalls.end(); ++it)
    {
        try
        {
            TestResult result = testSyscall(it.value());
            testResults.append(result);
            printResult(result);
            
            processedCount++;
            
            /* flush buffer periodically during processing */
            if (processedCount % OUTPUT_BATCH_SIZE == 0)
            {
                flushOutputBuffer();
            }
        }
        catch (const std::exception& e)
        {
            outputProgress(Colors::FAIL() + QString("Error Testing %1: %2").arg(it.key()).arg(e.what()) + Colors::ENDC());
            processedCount++;
        }
    }
    
    /* flush any remaining buffered output */
    flushOutputBuffer();

    int successCount = 0, failureCount = 0;

    for (const TestResult& result : testResults)
    {
        if (result.status == "SUCCESS")
        {
            successCount++;
        }
        else
        {
            failureCount++;
        }
    }

    outputProgress("");
    outputProgress(Colors::BOLD() + "Verification Summary:" + Colors::ENDC());
    outputProgress(QString("Total Syscalls Tested: %1").arg(testResults.size()));
    outputProgress(Colors::OKGREEN() + QString("Successful: %1").arg(successCount) + Colors::ENDC());
    outputProgress(Colors::FAIL() + QString("Failed: %1").arg(failureCount) + Colors::ENDC());
    outputProgress("");
}

void Verification::printResult(const TestResult& result)
{
    bool useAscii = false;
    QMap<QString, QString> treeChars;

    if (useAscii)
    {
        treeChars["branch"] = "|--";
        treeChars["last"] = "`--";
        treeChars["indent"] = "   ";
    }
    else
    {
        treeChars["branch"] = "├─";
        treeChars["last"] = "└─";
        treeChars["indent"] = "   ";
    }

    outputProgress(Colors::BOLD() + result.name + Colors::ENDC());
    QString statusColor = (result.status == "SUCCESS") ? Colors::OKGREEN() : Colors::FAIL();
    outputProgress(QString("%1 Status: %2%3%4").arg(treeChars["branch"]).arg(statusColor).arg(result.status).arg(Colors::ENDC()));
    outputProgress(QString("%1 Offset: 0x%2").arg(treeChars["branch"]).arg(result.offset.toLower().replace("h", "")));
    outputProgress(QString("%1 Return Type: %2").arg(treeChars["branch"]).arg(result.returnType));
    outputProgress(QString("%1 Parameters: %2").arg(treeChars["last"]).arg(result.parameterCount));

    if (!result.typeDefinitions.isEmpty())
    {
        outputProgress(QString("%1|-- Type Definitions:").arg(treeChars["indent"]));

        for (int i = 0; i < result.typeDefinitions.size(); ++i)
        {
            bool isLast = (i == result.typeDefinitions.size() - 1) && result.errors.isEmpty();
            QString prefix = isLast ? treeChars["last"] : treeChars["branch"];

            outputProgress(QString("%1   %2 %3: %4%5%6")
                         .arg(treeChars["indent"])
                         .arg(prefix)
                         .arg(result.typeDefinitions[i].first)
                         .arg(Colors::OKBLUE())
                         .arg(result.typeDefinitions[i].second)
                         .arg(Colors::ENDC()));
        }
    }

    if (!result.errors.isEmpty())
    {
        outputProgress(QString("%1|-- Errors:").arg(treeChars["indent"]));

        for (int i = 0; i < result.errors.size(); ++i)
        {
            QString prefix = (i == result.errors.size() - 1) ? treeChars["last"] : treeChars["branch"];

            outputProgress(QString("%1   %2 %3%4%5")
                         .arg(treeChars["indent"])
                         .arg(prefix)
                         .arg(Colors::FAIL())
                         .arg(result.errors[i])
                         .arg(Colors::ENDC()));
        }
    }

    outputProgress("");
}

QString Verification::getIniPath()
{
    return PathUtils::getIniPath();
}

QString Verification::getAsmFilePath(bool isKernelMode)
{
    return PathUtils::getSysCallerAsmPath(isKernelMode);
}

QString Verification::getHeaderFilePath(bool isKernelMode)
{
    return PathUtils::getSysFunctionsPath(isKernelMode);
}