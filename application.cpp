#include "application.h"
#include "ui_application.h"
#include "encryptor.h"
#include "rc4.h"
#include "rsa.h"
#include "gost.h"

#include <string>
#include <QMessageBox>
#include <QFileDialog>
#include <QtDebug>

Application::Application(QWidget *parent) : QMainWindow(parent), ui(new Ui::Application) {
    ui->setupUi(this);
    setMaximumSize(800, 600);
    setWindowIcon(QIcon("images/icon.ico"));

    algorithm = algorithmValueOf(ui->algorithmComboBox->currentText().toStdString());
    mode = modeValueOf(ui->modeComboBox->currentText().toStdString());

    for(auto groupBox : {ui->modeGroupBox, ui->algorithmGroupBox, ui->filesGroupBox,
                         ui->encryptionKeyGroupBox, ui->decryptionKeyGroupBox, ui->processingGroupBox,
                         ui->completedGroupBox}) {
        groupBox->move(260, 0);
        groupBox->hide();
    }
    stages.append(ui->welcomeGroupBox);
    stages.append(ui->modeGroupBox);
    stages.append(ui->algorithmGroupBox);
    stages.append(ui->filesGroupBox);
    if (mode == OperationMode::ENCRYPT) {
        stages.append(ui->encryptionKeyGroupBox);
    } else {
        stages.append(ui->decryptionKeyGroupBox);
    }
    stages.append(ui->processingGroupBox);
    stages.append(ui->completedGroupBox);
    currentGroupBox = new QList<QGroupBox*>::iterator(stages.begin());
}

Application::~Application() {
    delete ui;
}

std::string getDirectoryOfFile(std::string filePath) {
    return filePath.substr(0, filePath.find_last_of("/") + 1);
}

void Application::goToProcessing(QStringList &processedFiles, QStringList &failedFiles) {
    AbstractEncryptor *encryptor;
    QFile keyFile;
    if (mode == OperationMode::ENCRYPT) {
        keyFile.setFileName(ui->encryptionKeyLineEdit->text());
    } else {
        keyFile.setFileName(ui->decryptionKeyLineEdit->text());
    }

    std::vector<std::string> files;
    for (int i = 0; i < ui->fileList->count(); i++) {
        files.push_back(ui->fileList->item(i)->text().toStdString());
    }

    bool validEncryptor = false;
    if (mode == OperationMode::ENCRYPT && ui->randEncryptionKeyCheckBox->isChecked()) {
        std::string dir = getDirectoryOfFile(files.back());
        encryptor = generateEncryptor(algorithm, dir);
        validEncryptor = true;
    } else {
        if (keyFile.open(QFile::ReadOnly)) {
            QDataStream dataStream(&keyFile);
            std::vector<uint8_t> keyContainer(keyFile.size());

            auto iterator = keyContainer.begin();
            while (!dataStream.atEnd()) {
                dataStream >> *(iterator++);
            }
            keyFile.close();
            encryptor = generateEncryptor(algorithm, mode, keyContainer);
            validEncryptor = true;
        }
    }

    std::list<std::string> processedFilesStl;
    if (validEncryptor) {
        #ifdef QT_DEBUG
            encryptor->print();
        #endif
         qDebug();

        processFiles(*encryptor, mode, files, processedFilesStl);
    }

    for (auto filePath : processedFilesStl) {
        processedFiles.push_back(QString::fromStdString(filePath));
    }
    for (auto filePath : files) {
        failedFiles.push_back(QString::fromStdString(filePath));
    }

    delete(encryptor);
}

void Application::on_backButton_clicked() {
    currentGroupBox->i->t()->hide();
    (*currentGroupBox)--;
    if (currentGroupBox->i->t() == ui->welcomeGroupBox) {
        ui->backButton->setEnabled(false);
    }
    ui->nextButton->setEnabled(true);
    currentGroupBox->i->t()->show();
}

void Application::on_nextButton_clicked() {
    currentGroupBox->i->t()->hide();
    (*currentGroupBox)++;
    if (currentGroupBox->i->t() == ui->processingGroupBox) {
//        ui->nextButton->hide();
//        ui->backButton->hide();
    }
    if ((currentGroupBox->i->t() == ui->encryptionKeyGroupBox && ui->encryptionKeyLineEdit->text().isEmpty())
          || (currentGroupBox->i->t() == ui->decryptionKeyGroupBox && ui->decryptionKeyLineEdit->text().isEmpty())
            || (currentGroupBox->i->t() == ui->filesGroupBox && ui->fileList->count() == 0)) {
        ui->nextButton->setEnabled(false);
    }
    if (currentGroupBox->i->t() == ui->processingGroupBox) {
        QStringList processedFiles;
        QStringList failedFiles;
        goToProcessing(processedFiles, failedFiles);
    }
    currentGroupBox->i->t()->show();
    ui->backButton->setEnabled(true);
}

void Application::on_cancelButton_clicked() {
    auto exitReply = QMessageBox::question(this, "Exit", "Are you sure you want to exit the CryptQt?",
                                           QMessageBox::Yes | QMessageBox::No);
    if (exitReply == QMessageBox::Yes) {
        QApplication::quit();
    }
}

void Application::on_modeComboBox_currentTextChanged(const QString &value) {
    OperationMode newMode = modeValueOf(value.toStdString());
    if (mode != newMode) {
        ui->fileList->clear();
        mode = newMode;
        if (mode == OperationMode::ENCRYPT) {
            ui->encryptionKeyLineEdit->clear();
            ui->randEncryptionKeyCheckBox->setCheckState(Qt::CheckState::Unchecked);
            stages.replace(4, ui->encryptionKeyGroupBox);
        } else {
            ui->decryptionKeyLineEdit->clear();
            stages.replace(4, ui->decryptionKeyGroupBox);
        }
    }
}

void Application::on_algorithmComboBox_currentTextChanged(const QString &value) {
    EncryptionAlgorithm newAlgorithm = algorithmValueOf(value.toStdString());
    if (algorithm != newAlgorithm) {
        ui->fileList->clear();
        algorithm = newAlgorithm;
        if (mode == OperationMode::ENCRYPT) {
            ui->encryptionKeyLineEdit->clear();
            ui->randEncryptionKeyCheckBox->setCheckState(Qt::CheckState::Unchecked);
        } else {
            ui->decryptionKeyLineEdit->clear();
        }
    }
}

void Application::on_openFileButton_clicked() {
    QStringList filePathList = QFileDialog::getOpenFileNames(this, "Open file", "C://");
    if (!filePathList.isEmpty()) {
        ui->fileList->clear();
        ui->fileList->addItems(filePathList);
        ui->nextButton->setEnabled(true);
    }
}

void Application::on_openEncryptionKeyFileButton_clicked() {
    on_openKeyFileButton_clicked(ui->encryptionKeyLineEdit);
}

void Application::on_randEncryptionKeyCheckBox_stateChanged(int newState) {
    ui->encryptionKeyLineEdit->setEnabled(!newState);
    ui->openEncryptionKeyFileButton->setEnabled(!newState);
    if (currentGroupBox->i->t() == ui->encryptionKeyGroupBox) {
        ui->nextButton->setEnabled(newState || !ui->encryptionKeyLineEdit->text().isEmpty());
    }
}

void Application::on_openDecryptionKeyFileButton_clicked() {
    on_openKeyFileButton_clicked(ui->decryptionKeyLineEdit);
}

void Application::on_openKeyFileButton_clicked(QLineEdit *keyFileLineEdit) {
    QString filter;
    if (algorithm == EncryptionAlgorithm::RC4) {
        filter = "RC4 key (*.rc4key)";
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        filter = "RSA key (*.rsakey)";
    } else if (algorithm == EncryptionAlgorithm::GOST) {
        filter = "GOST key (*.gostkey)";
    }
    QString filePath = QFileDialog::getOpenFileName(this, "Open file", "C://", filter, &filter);
    if (!filePath.isEmpty()) {
        keyFileLineEdit->clear();
        keyFileLineEdit->setText(filePath);
        ui->nextButton->setEnabled(true);
    }
}
