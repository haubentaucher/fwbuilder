/*

                          Firewall Builder

  Central compile-time prolog/epilog directory hooks.

*/

#include "../../config.h"

#include "CentralHooks.h"

#include "fwbuilder/FWObject.h"
#include "fwbuilder/Firewall.h"
#include "fwbuilder/FWOptions.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSettings>
#include <QTextStream>
#include <QIODevice>
#include <QSet>

#include <cstdlib>

using namespace libfwbuilder;
using namespace std;

namespace {

bool isSafeNameComponent(const QString &name)
{
    if (name.isEmpty() || name == "." || name == "..") return false;
    for (int i = 0; i < name.size(); ++i)
    {
        const QChar ch = name.at(i);
        if (ch.isLetterOrNumber() || ch == '.' || ch == '_' || ch == '-')
            continue;
        return false;
    }
    return true;
}

bool isAllowedHookFile(const QFileInfo &info)
{
    if (!info.isFile()) return false;
    if (info.isSymLink()) return false;
    const QString name = info.fileName();
    if (name.startsWith('.')) return false;
    return name.endsWith(".sh");
}

QString settingsHooksKey()
{
    return QString("/") + GENERATION + "/Environment/HooksBaseDir";
}

QString applicationNameForSettings()
{
    return QString("FirewallBuilder") + GENERATION;
}

QString readProfilesMap(const QString &base_dir,
                        const QString &firewall_name,
                        QString *error)
{
    const QString map_path = QDir(base_dir).filePath("profiles.map");
    QFileInfo map_info(map_path);
    if (!map_info.exists()) return QString();
    if (map_info.isSymLink())
    {
        *error = QString("Central hooks profiles.map must not be a symbolic link: %1")
                     .arg(map_path);
        return QString();
    }
    if (!map_info.isFile())
    {
        *error = QString("Central hooks profiles.map is not a regular file: %1")
                     .arg(map_path);
        return QString();
    }

    QFile file(map_path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        *error = QString("Cannot read central hooks profiles.map: %1").arg(map_path);
        return QString();
    }

    QTextStream in(&file);
    int line_no = 0;
    while (!in.atEnd())
    {
        ++line_no;
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        const QStringList parts = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (parts.size() != 2)
        {
            *error = QString("Invalid profiles.map line %1 in %2")
                         .arg(line_no)
                         .arg(map_path);
            return QString();
        }
        if (parts.at(0) == firewall_name)
            return parts.at(1);
    }
    return QString();
}

bool collectDirFiles(const QString &dir_path,
                     const QString &base_canon,
                     QStringList *ordered_paths,
                     QSet<QString> *seen_canon,
                     QString *error)
{
    QFileInfo dir_info(dir_path);
    if (!dir_info.exists()) return true; // optional directory
    if (dir_info.isSymLink())
    {
        *error = QString("Central hooks directory must not be a symbolic link: %1")
                     .arg(dir_path);
        return false;
    }
    if (!dir_info.isDir())
    {
        *error = QString("Central hooks path is not a directory: %1").arg(dir_path);
        return false;
    }

    QDir dir(dir_path);
    QStringList names = dir.entryList(QDir::Files | QDir::Readable,
                                      QDir::Name);
    names.sort();
    for (int i = 0; i < names.size(); ++i)
    {
        const QString name = names.at(i);
        QFileInfo info(dir.filePath(name));
        if (!isAllowedHookFile(info))
        {
            // Documented: only regular *.sh files are loaded. Other
            // names are ignored without error so README files may sit
            // beside hooks.
            if (info.isSymLink())
            {
                *error = QString("Central hooks refuse symbolic links: %1")
                             .arg(info.filePath());
                return false;
            }
            continue;
        }
        if (!info.isReadable())
        {
            *error = QString("Central hooks file is not readable: %1")
                         .arg(info.filePath());
            return false;
        }

        const QString canon = info.canonicalFilePath();
        if (canon.isEmpty())
        {
            *error = QString("Cannot resolve central hooks file: %1")
                         .arg(info.filePath());
            return false;
        }
        if (!canon.startsWith(base_canon + "/") && canon != base_canon)
        {
            *error = QString("Central hooks file escapes the base directory: %1")
                         .arg(info.filePath());
            return false;
        }
        if (seen_canon->contains(canon))
            continue; // same file referenced twice in one compile
        seen_canon->insert(canon);
        ordered_paths->push_back(info.absoluteFilePath());
    }
    return true;
}

QString readHookFile(const QString &path, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        *error = QString("Cannot read central hooks file: %1").arg(path);
        return QString();
    }
    QTextStream in(&file);
    return in.readAll();
}

QString wrapHook(const QString &relative_label, const QString &body)
{
    QString out;
    QTextStream s(&out);
    // Avoid iptables marker substrings such as " -s " in comments.
    s << "# begin fwbuilder central hook: " << relative_label << "\n";
    if (!body.isEmpty() && !body.endsWith('\n'))
        s << body << "\n";
    else
        s << body;
    s << "# end fwbuilder central hook: " << relative_label << "\n";
    return out;
}

} // namespace

bool CentralHooks::platformSupportsShellHooks(const string &platform)
{
    return platform == "iptables"
        || platform == "nftables"
        || platform == "pf"
        || platform == "ipf"
        || platform == "ipfw";
}

QString CentralHooks::resolveBaseDir()
{
    const char *env = getenv("FWBUILDER_HOOKS_DIR");
    if (env && env[0] != '\0')
        return QString::fromLocal8Bit(env);

    QSettings settings(QSettings::UserScope,
                       "netcitadel.com",
                       applicationNameForSettings());
    return settings.value(settingsHooksKey()).toString().trimmed();
}

QString CentralHooks::normalizeBaseDir(const QString &configured, QString *error)
{
    if (configured.isEmpty()) return QString();

    QFileInfo info(configured);
    QString absolute = info.isAbsolute()
        ? info.absoluteFilePath()
        : QDir::current().absoluteFilePath(configured);

    QFileInfo abs_info(absolute);
    if (!abs_info.exists())
    {
        *error = QString("Configured central hooks base directory does not exist: %1")
                     .arg(absolute);
        return QString();
    }
    if (abs_info.isSymLink())
    {
        *error = QString("Configured central hooks base directory must not be a symbolic link: %1")
                     .arg(absolute);
        return QString();
    }
    if (!abs_info.isDir())
    {
        *error = QString("Configured central hooks base path is not a directory: %1")
                     .arg(absolute);
        return QString();
    }
    const QString canon = abs_info.canonicalFilePath();
    if (canon.isEmpty())
    {
        *error = QString("Cannot resolve central hooks base directory: %1")
                     .arg(absolute);
        return QString();
    }
    return canon;
}

QString CentralHooks::resolveProfile(Firewall *fw,
                                     const QString &base_dir,
                                     QString *error)
{
    FWOptions *options = fw->getOptionsObject();
    QString profile = QString::fromUtf8(
        options->getStr("hooks_profile").c_str()).trimmed();
    if (profile.isEmpty())
    {
        profile = readProfilesMap(
            base_dir,
            QString::fromUtf8(fw->getName().c_str()),
            error);
        if (!error->isEmpty()) return QString();
    }
    if (profile.isEmpty()) return QString();
    if (!isSafeNameComponent(profile))
    {
        *error = QString("Unsafe central hooks profile name: %1").arg(profile);
        return QString();
    }
    return profile;
}

QString CentralHooks::compose(Kind kind,
                              Firewall *fw,
                              const string &platform,
                              const string &gui_script,
                              QString *error)
{
    error->clear();
    const QString gui = QString::fromUtf8(gui_script.c_str());

    if (!platformSupportsShellHooks(platform))
        return gui;

    const QString configured = resolveBaseDir();
    if (configured.isEmpty())
        return gui;

    const QString base = normalizeBaseDir(configured, error);
    if (!error->isEmpty()) return QString();

    const QString platform_q = QString::fromStdString(platform);
    if (!isSafeNameComponent(platform_q))
    {
        *error = QString("Unsafe platform name for central hooks: %1")
                     .arg(platform_q);
        return QString();
    }

    const QString profile = resolveProfile(fw, base, error);
    if (!error->isEmpty()) return QString();

    const char *subdir = (kind == Prolog) ? "prolog.d" : "epilog.d";
    QStringList search_dirs;
    search_dirs << QDir(base).filePath(subdir);
    search_dirs << QDir(base).filePath(
        QString("platforms/%1/%2").arg(platform_q).arg(subdir));
    if (!profile.isEmpty())
    {
        search_dirs << QDir(base).filePath(
            QString("profiles/%1/%2").arg(profile).arg(subdir));
    }

    QStringList files;
    QSet<QString> seen;
    for (int i = 0; i < search_dirs.size(); ++i)
    {
        if (!collectDirFiles(search_dirs.at(i), base, &files, &seen, error))
            return QString();
    }

    QString composed;
    QTextStream out(&composed);
    for (int i = 0; i < files.size(); ++i)
    {
        const QString abs = files.at(i);
        QString relative = QDir(base).relativeFilePath(abs);
        QString body = readHookFile(abs, error);
        if (!error->isEmpty()) return QString();
        out << wrapHook(relative, body);
    }

    if (!gui.isEmpty())
    {
        out << "# begin fwbuilder object hook\n";
        if (!gui.endsWith('\n'))
            out << gui << "\n";
        else
            out << gui;
        out << "# end fwbuilder object hook\n";
    }

    return composed;
}

QString CentralHooks::composeOrAbort(Kind kind,
                                     Firewall *fw,
                                     const string &platform,
                                     const string &gui_script,
                                     string *error_out)
{
    QString error;
    QString text = compose(kind, fw, platform, gui_script, &error);
    if (!error.isEmpty())
    {
        if (error_out) *error_out = error.toStdString();
        return QString();
    }
    if (error_out) error_out->clear();
    return text;
}
