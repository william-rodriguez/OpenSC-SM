TOPDIR = ..\..

# TARGET = smm-local.dll

# OBJECTS = smm-local.obj sm-common.obj sm-global-platform.obj sm-iasecc.obj sm-authentic.obj

all: $(TARGET)

!INCLUDE $(TOPDIR)\win32\Make.rules.mak

$(TARGET): $(OBJECTS) ..\libopensc\opensc.lib 
	copy smm-local.exports.orig  smm-local.exports
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) $(OBJECTS) ..\libopensc\opensc.lib winscard.lib $(OPENSSL_LIB) $(MOZILLA_LIB) gdi32.lib $(LIBLTDL_LIB)
	if EXIST $(TARGET).manifest mt -manifest $(TARGET).manifest -outputresource:$(TARGET);2

smm-local.obj: smm-local.c
	cl $(COPTS) /c smm-local.c

.c.obj:
	cl $(COPTS) /c $<
