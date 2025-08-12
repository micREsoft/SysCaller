#pragma once

#include <QString>
#include <QMap>
#include <QVariantMap>
#include <QPair>
#include <vector>
#include <cstdint>
#include <pe-parse/parse.h>

class SyscallExtractor {
public:
    static QMap<QString, int> getSyscallsFromDll(const QString& dllPath);
    static bool rvaToFileOffset(peparse::parsed_pe* pe, uint32_t rva, uint32_t& fileOffset);
    static size_t readBytesFromBuffer(const peparse::bounded_buffer* buffer,
                                      uint32_t offset,
                                      size_t size,
                                      std::vector<uint8_t>& data);
};

class StubHashGenerator {
public:
    static QVariantMap generateStubHashes(const QString& asmFilePath,
                                          const QString& headerFilePath,
                                          const QString& obfuscationMethod = QString());
    static QPair<bool, QString> saveStubHashes(const QVariantMap& stubHashes,
                                              const QString& timestamp = QString());
};

class InlineAssemblyConverter {
public:
    static QString convertStubToInline(const QString& stubName, int syscallId);
};