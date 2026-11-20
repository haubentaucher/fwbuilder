# Native nftables compiler imported from amarce/fwbuilder.
# Qt5/qmake adapter for the preserved 5.3.8 build.
include(../../qmake.inc)
TEMPLATE = lib
CONFIG += staticlib c++11
TARGET = nftlib
SOURCES += CompilerDriver_nft_policy.cpp \
    CompilerDriver_nft.cpp \
    CompilerDriver_nft_nat.cpp \
    CompilerDriver_nft_run.cpp \
    OSConfigurator_linux24_nft.cpp \
    OSData_nft.cpp \
    PolicyCompiler_nft_optimizer.cpp \
    PolicyCompiler_nft.cpp \
    PolicyCompiler_PrintRule_nft.cpp \
    PolicyCompiler_PrintRuleNftRst.cpp \
    PolicyCompiler_PrintRuleNftRstEcho.cpp \
    MangleTableCompiler_nft.cpp \
    NATCompiler_nft.cpp \
    NATCompiler_PrintRule_nft.cpp \
    NATCompiler_PrintRuleNftRst.cpp \
    NATCompiler_PrintRuleNftRstEcho.cpp \
    nft_utils.cpp \
    RoutingCompiler_nft.cpp \
    RoutingCompiler_nft_writers.cpp
HEADERS += ../../config.h \
    CompilerDriver_nft.h \
    MangleTableCompiler_nft.h \
    NATCompiler_nft.h \
    OSConfigurator_linux24_nft.h \
    OSData_nft.h \
    PolicyCompiler_nft.h \
    RoutingCompiler_nft.h \
    nft_utils.h \
    nftables_options.h
INCLUDEPATH += ../iptlib ../compiler_lib ../libfwbuilder/src
DEPENDPATH += ../iptlib ../compiler_lib ../libfwbuilder/src
INSTALLS -= target
