# Native nftables CLI. The older compilers remain unmodified.
include(../../qmake.inc)
QT -= gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG += c++11
SOURCES = nft.cpp
HEADERS = ../../config.h
INCLUDEPATH += ../nftlib ../iptlib ../compiler_lib ../libfwbuilder/src
DEPENDPATH += ../nftlib ../iptlib ../compiler_lib ../libfwbuilder/src
!win32:QMAKE_COPY = ../../install.sh -m 0755
win32:CONFIG += console
PRE_TARGETDEPS = ../common/$$BINARY_SUBDIR/libcommon.a \
    ../nftlib/$$BINARY_SUBDIR/libnftlib.a \
    ../iptlib/$$BINARY_SUBDIR/libiptlib.a \
    ../compiler_lib/$$BINARY_SUBDIR/libcompilerdriver.a \
    ../libfwbuilder/src/fwcompiler/$$BINARY_SUBDIR/libfwcompiler.a \
    ../libfwbuilder/src/fwbuilder/$$BINARY_SUBDIR/libfwbuilder.a
LIBS += $$PRE_TARGETDEPS $$LIBS
TARGET = fwb_nft
