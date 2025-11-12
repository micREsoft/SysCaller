#include <Core/Utils/Common.h>
#include <GUI/Settings.h>

IntegrityTab::IntegrityTab(QSettings* settings, QWidget* parent)
    : QWidget(parent)
    , settings(settings)
{
    initUI();
}

void IntegrityTab::initUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);

    QGroupBox* syscallGroup = new QGroupBox("Syscall Selection");
    syscallGroup->setToolTip("Select which syscalls to include in the final build");

    QVBoxLayout* syscallLayout = new QVBoxLayout();

    QLabel* desc = new QLabel("Select the syscalls to include in the final build. Only selected syscalls will be processed during integrity checks and included in the final build!");
    desc->setWordWrap(true);
    syscallLayout->addWidget(desc);

    QHBoxLayout* selectLayout = new QHBoxLayout();

    QPushButton* selectAllBtn = new QPushButton("Select All");
    connect(selectAllBtn, &QPushButton::clicked, this, &IntegrityTab::selectAllSyscalls);
    selectLayout->addWidget(selectAllBtn);

    QPushButton* selectNoneBtn = new QPushButton("Select None");
    connect(selectNoneBtn, &QPushButton::clicked, this, &IntegrityTab::selectNoSyscalls);
    selectLayout->addWidget(selectNoneBtn);

    filterEdit = new QLineEdit();
    filterEdit->setPlaceholderText("Filter syscalls...");
    connect(filterEdit, &QLineEdit::textChanged, this, &IntegrityTab::filterSyscalls);
    selectLayout->addWidget(filterEdit, 1);
    syscallLayout->addLayout(selectLayout);

    syscallList = new QListWidget();
    syscallList->setSelectionMode(QAbstractItemView::NoSelection);
    syscallLayout->addWidget(syscallList);
    syscallGroup->setLayout(syscallLayout);
    layout->addWidget(syscallGroup);

    loadSyscalls();
}

void IntegrityTab::loadSyscalls()
{
    syscalls.clear();
    PathUtils::debugPathDetection();

    QString projectRoot = PathUtils::getProjectRoot();
    qDebug() << "Project root:" << projectRoot;

    QString syscallMode = settings->value("general/syscall_mode", "Nt").toString();
    bool isKernelMode = (syscallMode == "Zw");
    QString syscallPrefix = (syscallMode == "Nt") ? "Sys" : "SysK";
    QString headerPath = PathUtils::getSysFunctionsPath(isKernelMode);

    qDebug() << "Header path:" << headerPath;
    qDebug() << "Header file exists:" << QFile::exists(headerPath);

    QStringList selectedSyscalls = settings->value("integrity/selected_syscalls", QStringList()).toStringList();

    QFile file(headerPath);

    if (file.exists() && file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qDebug() << "Successfully opened header file:" << headerPath;

        QTextStream stream(&file);
        stream.setCodec("UTF-8");
        int lineCount = 0;

        while (!stream.atEnd())
        {
            QString line = stream.readLine();
            lineCount++;

            QRegExp externCRegex(QString(R"(extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) (%1\w+)\()").arg(syscallPrefix));

            if (externCRegex.indexIn(line) != -1)
            {
                QString syscall = externCRegex.cap(1);
                qDebug() << "Found extern C syscall:" << syscall;
                syscalls.append(syscall);
                continue;
            }

            QRegExp regularRegex(QString(R"((?:NTSTATUS|ULONG|BOOLEAN|VOID) (%1\w+)\()").arg(syscallPrefix));

            if (regularRegex.indexIn(line) != -1)
            {
                QString syscall = regularRegex.cap(1);
                qDebug() << "Found regular syscall:" << syscall;
                syscalls.append(syscall);
                continue;
            }

            QRegExp scExternCRegex(R"(extern "C" (?:NTSTATUS|ULONG|BOOLEAN|VOID) (SC\w+)\()");

            if (scExternCRegex.indexIn(line) != -1)
            {
                QString scName = scExternCRegex.cap(1);
                QString syscallName = syscallPrefix + scName.mid(2);
                qDebug() << "Found SC extern C syscall:" << scName << "->" << syscallName;
                syscalls.append(syscallName);
                continue;
            }

            QRegExp scRegularRegex(R"((?:NTSTATUS|ULONG|BOOLEAN|VOID) (SC\w+)\()");

            if (scRegularRegex.indexIn(line) != -1)
            {
                QString scName = scRegularRegex.cap(1);
                QString syscallName = syscallPrefix + scName.mid(2);
                qDebug() << "Found SC regular syscall:" << scName << "->" << syscallName;
                syscalls.append(syscallName);
                continue;
            }
        }

        qDebug() << "Processed" << lineCount << "lines from header file";
        file.close();
    }
    else
    {
        qWarning() << "Failed to open header file:" << headerPath;
        qWarning() << "File exists:" << file.exists();
        qWarning() << "File error:" << file.errorString();
    }

    syscalls.sort();
    qDebug() << "Found" << syscalls.size() << "syscalls";

    for (const QString& syscall : syscalls)
    {
        qDebug() << "  " << syscall;
    }

    if (selectedSyscalls.isEmpty())
    {
        selectedSyscalls = syscalls;
    }

    for (const QString& syscall : syscalls)
    {
        QListWidgetItem* item = new QListWidgetItem(syscall);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);

        if (selectedSyscalls.contains(syscall))
        {
            item->setCheckState(Qt::Checked);
        }
        else
        {
            item->setCheckState(Qt::Unchecked);
        }

        syscallList->addItem(item);
    }
}

void IntegrityTab::selectAllSyscalls()
{
    for (int i = 0; i < syscallList->count(); ++i)
    {
        QListWidgetItem* item = syscallList->item(i);

        if (!item->isHidden())
        {
            item->setCheckState(Qt::Checked);
        }
    }
}

void IntegrityTab::selectNoSyscalls()
{
    for (int i = 0; i < syscallList->count(); ++i)
    {
        QListWidgetItem* item = syscallList->item(i);

        if (!item->isHidden())
        {
            item->setCheckState(Qt::Unchecked);
        }
    }
}

void IntegrityTab::filterSyscalls(const QString& text)
{
    for (int i = 0; i < syscallList->count(); ++i)
    {
        QListWidgetItem* item = syscallList->item(i);

        if (text.isEmpty() || item->text().toLower().contains(text.toLower()))
        {
            item->setHidden(false);
        }
        else
        {
            item->setHidden(true);
        }
    }
}

void IntegrityTab::saveSettings()
{
    QStringList selectedSyscalls;

    for (int i = 0; i < syscallList->count(); ++i)
    {
        QListWidgetItem* item = syscallList->item(i);

        if (item->checkState() == Qt::Checked)
        {
            selectedSyscalls.append(item->text());
        }
    }

    settings->setValue("integrity/selected_syscalls", selectedSyscalls);
}