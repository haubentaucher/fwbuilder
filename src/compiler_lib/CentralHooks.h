/*

                          Firewall Builder

  Central compile-time prolog/epilog hooks loaded from configured
  directories on the compiler host. The resulting text is embedded in
  the generated firewall script; nothing is transferred separately.

*/

#ifndef __CENTRAL_HOOKS_HH__
#define __CENTRAL_HOOKS_HH__

#include <string>

#include <QString>
#include <QStringList>

namespace libfwbuilder {
    class Firewall;
};

class CentralHooks
{
public:
    enum Kind { Prolog = 0, Epilog = 1 };

    // Shell-script backends only. Device-CLI backends are excluded.
    static bool platformSupportsShellHooks(const std::string &platform);

    // Resolve the configured base directory.
    // Order: FWBUILDER_HOOKS_DIR, then QSettings Environment/HooksBaseDir.
    // Empty string means the feature is disabled (legacy behaviour).
    static QString resolveBaseDir();

    // Absolute or relative to the process current directory.
    static QString normalizeBaseDir(const QString &configured, QString *error);

    // Explicit profile for this firewall: FWOptions "hooks_profile",
    // else profiles.map in the base directory. Never inferred from hostname.
    static QString resolveProfile(libfwbuilder::Firewall *fw,
                                  const QString &base_dir,
                                  QString *error);

    // Compose central files plus the existing GUI script. On error,
    // *error is set and the return value is empty.
    static QString compose(Kind kind,
                           libfwbuilder::Firewall *fw,
                           const std::string &platform,
                           const std::string &gui_script,
                           QString *error);

    // Convenience used by compiler drivers.
    static QString composeOrAbort(Kind kind,
                                  libfwbuilder::Firewall *fw,
                                  const std::string &platform,
                                  const std::string &gui_script,
                                  std::string *error_out);
};

#endif
