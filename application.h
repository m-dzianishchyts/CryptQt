#pragma once

#include "encryptor.h"

#include <QMainWindow>
#include <QGroupBox>
#include <QLineEdit>

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

    void on_openEncryptionKeyFileButton_clicked();

    void on_openDecryptionKeyFileButton_clicked();

    void on_randEncryptionKeyCheckBox_stateChanged(int newState);

    void keyFileError();

private:
    Ui::Application *ui;

    QList<QGroupBox*>::iterator *currentGroupBox;
    QList<QGroupBox*> stages;
    OperationMode mode;
    EncryptionAlgorithm algorithm;
    std::vector<uint8_t> *key;
    bool onExit = false;
    bool inDialog = false;
    bool keyError = false;

    void goToProcessing();
    void on_openKeyFileButton_clicked(QLineEdit *keyFileLineEdit);
};
