#include <Core/Obfuscation/Direct/Direct.h>
#include <Core/Utils/QtDependencies.h>

DirectObfuscation::JunkGenerator::JunkGenerator(QSettings* settings)
    : settings(settings)
{}

void DirectObfuscation::JunkGenerator::setSettings(QSettings* settings)
{
    this->settings = settings;
}

QString DirectObfuscation::JunkGenerator::generateJunkInstructions(int minInst, int maxInst, bool useAdvanced)
{
    /* rcx, rdx, r8, r9 are function parameters, NEVER touch these!
       rbx, rsi, rdi, r12 are used to save rcx, rdx, r8, r9, NEVER touch these!
       r10 is used for function pointer, NEVER touch this!
       so we can ONLY safely use: r11, r13, r14, r15, rax */
    
    if (!settings)
    {
        return "";
    }

    if (minInst == -1)
    {
        minInst = settings->value("obfuscation/min_instructions", 2).toInt();
    }

    if (maxInst == -1)
    {
        maxInst = settings->value("obfuscation/max_instructions", 8).toInt();
    }

    if (!useAdvanced)
    {
        useAdvanced = settings->value("obfuscation/use_advanced_junk", false).toBool();
    }
    QStringList junkInstructions =
    {
        "    nop\n",
        "    xchg r11, r11\n",
        "    xchg r13, r13\n",
        "    xchg r14, r14\n",
        "    xchg r15, r15\n",
        "    xchg rax, rax\n",
        "    test r11, r11\n",
        "    test r13, r13\n",
        "    test r14, r14\n",
        "    test r15, r15\n",
        "    lea r11, [r11]\n",
        "    lea r13, [r13]\n",
        "    lea r14, [r14]\n",
        "    lea r15, [r15]\n",
        "    mov r11, r11\n",
        "    mov r13, r13\n",
        "    mov r14, r14\n",
        "    mov r15, r15\n",
        "    mov r12, r11\n    mov r11, r12\n",
        "    mov r12, r13\n    mov r13, r12\n",
        "    mov r12, r14\n    mov r14, r12\n",
        "    mov r12, r15\n    mov r15, r12\n",
        "    xor r11, 0\n",
        "    xor r13, 0\n",
        "    xor r14, 0\n",
        "    xor r15, 0\n"
    };

    if (useAdvanced)
    {
        QStringList advancedJunk =
        {
            "    pause\n",
            "    fnop\n",
            "    cld\n",
            "    clc\n",
            "    cmc\n    cmc\n",
            "    and r13d, -1\n",
            "    add r15d, 0\n",
            "    sub rax, 0\n",
            "    db 66h\n    nop\n",
            "    db 0Fh, 1Fh, 00h\n",
            "    db 0Fh, 1Fh, 40h, 00h\n",
            "    db 0Fh, 1Fh, 44h, 00h, 00h\n",
            "    db 66h, 0Fh, 1Fh, 44h, 00h, 00h\n",
            "    shl r11, 0\n",
            "    shr r13, 0\n",
            "    ror r14, 0\n",
            "    rol r15, 0\n",
            "    bswap rax\n    bswap rax\n",
            "    inc r14\n    dec r14\n",
            "    dec r15\n    inc r15\n",
            "    lahf\n    sahf\n",
            "    lfence\n",
            "    sfence\n",
            "    mfence\n"
        };

        int advancedCount = getRandomInt(2, 8);

        for (int i = 0; i < advancedCount; ++i)
        {
            junkInstructions.append(advancedJunk[getRandomInt(0, advancedJunk.size() - 1)]);
        }
    }

    int numInstructions = getRandomInt(minInst, maxInst);
    QString result;

    for (int i = 0; i < numInstructions; ++i)
    {
        result += junkInstructions[getRandomInt(0, junkInstructions.size() - 1)];
    }

    return result;
}

QString DirectObfuscation::JunkGenerator::getRandomJunkInstruction()
{
    QStringList instructions =
    {
        "    nop\n",
        "    xchg r8, r8\n",
        "    test r8, r8\n"
    };

    return instructions[getRandomInt(0, instructions.size() - 1)];
}

QString DirectObfuscation::JunkGenerator::getRandomAdvancedJunkInstruction()
{
    QStringList instructions =
    {
        "    pause\n",
        "    fnop\n",
        "    cld\n"
    };

    return instructions[getRandomInt(0, instructions.size() - 1)];
}

int DirectObfuscation::JunkGenerator::getRandomInt(int min, int max)
{
    return QRandomGenerator::global()->bounded(min, max + 1);
}