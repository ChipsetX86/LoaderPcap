QT -= gui
QT += network sql

CONFIG += c++11 console
CONFIG -= app_bundle

SOURCES += \
        PcapReader.cpp \
        main.cpp

HEADERS += \
    PcapReader.h

INCLUDEPATH += pcap
LIBS += -L"$${PWD}\bin" -lpcap
win32:LIBS += -lWs2_32

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

