#-*- mode: makefile; tab-width: 4; -*-
#
# This library is separate from fwcompiler library because it has dependency
# on QT

include(../../qmake.inc)

TEMPLATE = lib

SOURCES	 =  CompilerDriver.cpp \
			CompilerDriver_files.cpp \
			CompilerDriver_compile.cpp \
			CompilerDriver_generators.cpp \
			Configlet.cpp \
			interfaceProperties.cpp \
			linux24Interfaces.cpp \
			openbsdInterfaces.cpp \
			freebsdInterfaces.cpp \
			interfacePropertiesObjectFactory.cpp \
			AutomaticRules.cpp \
			CentralHooks.cpp

HEADERS	 = ../../config.h \
			CompilerDriver.h \
			Configlet.h \
			interfaceProperties.h \
			linux24Interfaces.h \
			openbsdInterfaces.h \
			freebsdInterfaces.h \
			interfacePropertiesObjectFactory.h \
			AutomaticRules.h \
			CentralHooks.h

INCLUDEPATH += ../libfwbuilder/src
DEPENDPATH  += ../libfwbuilder/src

CONFIG += staticlib

TARGET = compilerdriver

INSTALLS -= target
