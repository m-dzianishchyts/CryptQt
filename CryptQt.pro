QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    encryptor.cpp \
    gost.cpp \
    main.cpp \
    application.cpp \
    mathutils.cpp \
    rc4.cpp \
    rsa.cpp

HEADERS += \
    application.h \
    encryptor.h \
    gost.h \
    mathutils.h \
    rc4.h \
    rsa.h

FORMS += \
    application.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RC_ICONS = images/icon.ico

RESOURCES += \
    images.qrc
