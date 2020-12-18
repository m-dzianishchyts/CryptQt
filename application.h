#pragma once

#include "encryptor.h"

#include <QMainWindow>
#include <QGroupBox>

QT_BEGIN_NAMESPACE
namespace Ui { class Application; }
QT_END_NAMESPACE

class Application : public QMainWindow {
    Q_OBJECT

public:
    Application(QWidget *parent = nullptr);
    ~Application();

private slots:
    void on_backButton_clicked();

    void on_nextButton_clicked();

    void on_cancelButton_clicked();

    void on_modeComboBox_currentTextChanged(const QString &arg1);

    void on_algorithmComboBox_currentTextChanged(const QString &arg1);

    void on_openFileButton_clicked();

    void on_openKeyFileButton_clicked();

    void on_keyRC4LineEdit_textEdited(const QString &arg1);

    void on_randRC4keyCheckBox_stateChanged(int arg1);

private:
    Ui::Application *ui;

    QList<QGroupBox*>::iterator *currentGroupBox;
    OperationMode mode;
    EncryptionAlgorithm algorithm;

    QList<QGroupBox*> stages;
};
