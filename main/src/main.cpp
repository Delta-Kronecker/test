#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include "../include/Utils.h"
#include "../include/HttpHelper.h"
#include "../include/SubParser.h"

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "=== ConfigCollector Started ===";

    // Read Sub.txt
    QString subFilePath = "../data/Sub.txt";
    QString subContent = ReadFileText(subFilePath);

    if (subContent.isEmpty()) {
        qDebug() << "Error: Sub.txt is empty or not found!";
        qDebug() << "Please create" << QDir::current().absoluteFilePath(subFilePath);
        return 1;
    }

    auto subLinks = subContent.split('\n', Qt::SkipEmptyParts);
    qDebug() << "Found" << subLinks.size() << "subscription links";

    int totalConfigs = 0;
    int configIndex = 1;

    // Process each subscription link
    for (int i = 0; i < subLinks.size(); i++) {
        auto link = subLinks[i].trimmed();
        if (link.isEmpty() || link.startsWith("#")) continue;

        qDebug() << "\n[" << (i+1) << "/" << subLinks.size() << "] Processing:" << link;

        // Download subscription
        auto response = HttpHelper::HttpGet(link);

        if (!response.error.isEmpty()) {
            qDebug() << "  Error downloading:" << response.error;
            continue;
        }

        qDebug() << "  Downloaded" << response.data.size() << "bytes";

        // Parse subscription
        auto beans = SubParser::ParseSubscription(QString::fromUtf8(response.data));
        qDebug() << "  Parsed" << beans.size() << "configs";

        // Save each config as JSON
        for (const auto &bean : beans) {
            auto json = bean->ToJson();
            auto jsonStr = QJsonObject2QString(json, false);

            QString filename = QString("../data/Config/config_%1.json").arg(configIndex, 4, 10, QChar('0'));

            if (WriteFileText(filename, jsonStr)) {
                qDebug() << "  Saved:" << filename << "-" << bean->name;
                configIndex++;
                totalConfigs++;
            } else {
                qDebug() << "  Error saving:" << filename;
            }
        }
    }

    qDebug() << "\n=== ConfigCollector Finished ===";
    qDebug() << "Total configs saved:" << totalConfigs;

    return 0;
}