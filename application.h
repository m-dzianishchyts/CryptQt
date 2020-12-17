#pragma once

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

private:
    Ui::Application *ui;

    QList<QGroupBox*>::iterator *currentGroupBox;
    QString *mode;
    QString *encryptionAlgorithm;

    QList<QGroupBox*> stages;
};
