#-*- mode: makefile; tab-width: 4; -*-
#
include(../../qmake.inc)
#
TEMPLATE = lib
#

SOURCES	 =			IPTCfgLexer.cpp  \
			IPTCfgParser.cpp \
			PFCfgLexer.cpp  \
			PFCfgParser.cpp \

HEADERS	 = ../../config.h    \
			IPTCfgLexer.hpp  \
			IPTCfgParser.hpp \
			IPTCfgParserTokenTypes.hpp \
			PFCfgLexer.hpp  \
			PFCfgParser.hpp \
			PFCfgParserTokenTypes.hpp \


CONFIG += staticlib

INCLUDEPATH += $$ANTLR_INCLUDEPATH ../import ../libfwbuilder/src
DEPENDPATH  += $$ANTLR_INCLUDEPATH ../import ../libfwbuilder/src

LIBS += $$ANTLR_LIBS
DEFINES += $$ANTLR_DEFINES

TARGET   = fwbparser

INSTALLS -= target
