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
#include <QMovie>
#include <QThread>

Application::Application(QWidget *parent) : QMainWindow(parent), ui(new Ui::Application) {
    ui->setupUi(this);
    setMaximumSize(800, 600);
    setWindowIcon(QIcon(":/images/icon.ico"));

    auto movie = new QMovie(":/images/loading.gif");
    ui->loadingLabel->setMovie(movie);
    ui->loadingLabel->setScaledContents(true);
    movie->start();

    algorithm = algorithmValueOf(ui->algorithmComboBox->currentText().toStdString());
    mode = modeValueOf(ui->modeComboBox->currentText().toStdString());


    ui->loadingLabel->hide();
    ui->progressLabel->hide();
    for(auto groupBox : {ui->modeGroupBox, ui->algorithmGroupBox, ui->filesGroupBox,
                         ui->encryptionKeyGroupBox, ui->decryptionKeyGroupBox, ui->completedGroupBox}) {
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
    stages.append(ui->completedGroupBox);
    currentGroupBox = new QList<QGroupBox*>::iterator(stages.begin());
    files = new std::vector<std::string>();
    generatedKeys = new std::list<std::string>;
    processedFiles = new std::vector<std::string>;
}

Application::~Application() {
    delete(ui->loadingLabel->movie());
    delete(ui);
    delete(currentGroupBox);
}

std::string getDirectoryOfFile(std::string filePath) {
    return filePath.substr(0, filePath.find_last_of("/") + 1);
}

void goToProcessing(const QString keyFilePath, std::vector<std::string> *files,
                    EncryptionAlgorithm algorithm, OperationMode mode, bool randomKey,
                    bool *keyError, bool *onExit, bool *inDialog, QLabel *progressLabel,
                    std::list<std::string> *generatedKeys, std::vector<std::string> *processedFiles) {
    AbstractEncryptor *encryptor = nullptr;
    QFile inputkeyFile(keyFilePath);
    bool validEncryptor = false;
    if (mode == OperationMode::ENCRYPT && randomKey) {
        std::string dir = getDirectoryOfFile(files->back());
        encryptor = generateEncryptor(algorithm, dir, *generatedKeys);
        validEncryptor = true;
    } else {
        if (inputkeyFile.open(QFile::ReadOnly)) {
            QDataStream dataStream(&inputkeyFile);
            std::vector<uint8_t> keyContainer(inputkeyFile.size());

            auto iterator = keyContainer.begin();
            while (!dataStream.atEnd()) {
                dataStream >> *(iterator++);
            }
            inputkeyFile.close();
            encryptor = generateEncryptor(algorithm, mode, keyContainer);
            validEncryptor = true;
        } else {
            *keyError = true;
        }
    }

    if (encryptor != nullptr) {
        std::list<std::string> processedFilesStl;
        if (validEncryptor) {
            #ifdef QT_DEBUG
                encryptor->print();
            #endif
            qDebug();
            processFiles(*encryptor, mode, *onExit, *files, processedFilesStl, *progressLabel);
        }

        for (const auto &filePath : processedFilesStl) {
            processedFiles->push_back(filePath);
        }


        while (*inDialog) {
            QThread::sleep(1);
        }

        if (*onExit) {
            for (const auto &filePath : processedFilesStl) {
                remove(filePath.c_str());
            }
            if (mode == OperationMode::ENCRYPT && randomKey) {
                for (const auto &filePath : *generatedKeys) {
                   remove(filePath.c_str());
                }
            }
        }
        delete(encryptor);
    }
}

void Application::on_backButton_clicked() {
    if (currentGroupBox->i->t() == ui->decryptionKeyGroupBox || currentGroupBox->i->t() == ui->encryptionKeyGroupBox) {
        ui->nextButton->setText("Next >");
    }
    currentGroupBox->i->t()->hide();
    (*currentGroupBox)--;
    if (currentGroupBox->i->t() == ui->welcomeGroupBox) {
        ui->backButton->setEnabled(false);
    }
    ui->nextButton->setEnabled(true);
    currentGroupBox->i->t()->show();
}

void Application::on_nextButton_clicked() {
    if (currentGroupBox->i->t() == ui->decryptionKeyGroupBox || currentGroupBox->i->t() == ui->encryptionKeyGroupBox) {
        ui->nextButton->hide();
        ui->backButton->hide();
        ui->loadingLabel->show();
        ui->progressLabel->show();
        currentGroupBox->i->t()->setEnabled(false);

        files->clear();
        for (int i = 0; i < ui->fileList->count(); i++) {
            files->push_back(ui->fileList->item(i)->text().toStdString());
        }
        QString keyFilePath;
        if (currentGroupBox->i->t() == ui->encryptionKeyGroupBox) {
            keyFilePath = ui->encryptionKeyLineEdit->text();
        } else {
            keyFilePath = ui->decryptionKeyLineEdit->text();
        }
        auto workerFiles = files;
        auto workerAlgorithm = algorithm;
        auto workerMode = mode;
        auto workerRandomKey = ui->randEncryptionKeyCheckBox->isChecked();
        auto workerKeyError = &keyError;
        auto workerOnExit = &onExit;
        auto workerInDialog = &inDialog;
        auto workerProgressLabel = ui->progressLabel;
        auto workerGeneratedKeys = generatedKeys;
        auto workerProcessedFiles = processedFiles;
        QThread *worker = QThread::create([keyFilePath, workerFiles, workerAlgorithm, workerMode, workerRandomKey,
                                          workerKeyError, workerOnExit, workerInDialog, workerProgressLabel,
                                          workerGeneratedKeys, workerProcessedFiles] {
            goToProcessing(keyFilePath, workerFiles, workerAlgorithm, workerMode, workerRandomKey, workerKeyError,
                           workerOnExit, workerInDialog, workerProgressLabel, workerGeneratedKeys, workerProcessedFiles);
        });
        connect(worker, &QThread::finished, this, &Application::workerFinished);
        worker->start();
    } else {
        currentGroupBox->i->t()->hide();
        (*currentGroupBox)++;
        if ((currentGroupBox->i->t() == ui->encryptionKeyGroupBox &&
             (ui->encryptionKeyLineEdit->text().isEmpty() && !ui->randEncryptionKeyCheckBox->isChecked()))
              || (currentGroupBox->i->t() == ui->decryptionKeyGroupBox && ui->decryptionKeyLineEdit->text().isEmpty())
                || (currentGroupBox->i->t() == ui->filesGroupBox && ui->fileList->count() == 0)) {
            ui->nextButton->setEnabled(false);
        }
        if (currentGroupBox->i->t() == ui->decryptionKeyGroupBox || currentGroupBox->i->t() == ui->encryptionKeyGroupBox) {
            ui->nextButton->setText("Run");
        }
        if (currentGroupBox->i->t() == ui->completedGroupBox) {
            ui->cancelButton->setText("Exit");
            ui->loadingLabel->hide();
            ui->progressLabel->hide();
        }
        currentGroupBox->i->t()->show();
        ui->backButton->setEnabled(true);
    }
}

void Application::on_cancelButton_clicked() {
    if (currentGroupBox->i->t() == ui->completedGroupBox) {
        close();
    } else {
        inDialog = true;
        auto exitReply = QMessageBox::question(this, "Exit", "Are you sure you want to exit the CryptQt?",
                                               QMessageBox::Yes | QMessageBox::No);
        if (exitReply == QMessageBox::Yes) {
            if (currentGroupBox->i->t() == ui->decryptionKeyGroupBox || currentGroupBox->i->t() == ui->encryptionKeyGroupBox) {
                onExit = true;
                ui->progressLabel->setText("Canceling...");
            } else {
                close();
            }
        }
    inDialog = false;
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
    QStringList filePathList;
    if (mode == OperationMode::DECRYPT) {
        QString filter;
        if (algorithm == EncryptionAlgorithm::RC4) {
            filter = "RC4 encrypted (*.rc4)";
        } else if (algorithm == EncryptionAlgorithm::RSA) {
            filter = "RSA encrypted (*.rsa)";
        } else if (algorithm == EncryptionAlgorithm::GOST28147_89) {
            filter = "GOST28147_89 encrypted (*.gost)";
        }
        filePathList = QFileDialog::getOpenFileNames(this, "Open file", "C://", filter);
    } else {
        filePathList = QFileDialog::getOpenFileNames(this, "Open file", "C://");
    }
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

void Application::workerFinished()
{
    if (keyError) {
        QMessageBox::critical(this, "Key file error",
            "The selected key file was not found. Select the key file again.",
            QMessageBox::StandardButton::Ok);
        currentGroupBox->i->t()->setEnabled(true);
        ui->loadingLabel->hide();
        ui->progressLabel->hide();
        ui->nextButton->show();
        ui->backButton->show();
        keyError = false;
    } else if (onExit) {
        close();
    } else {
        ui->processedFileList->clear();
        for (const auto &filePath : *processedFiles) {
            ui->processedFileList->addItem(QString::fromStdString(*(new std::string(filePath))));
        }
        for (const auto &filePath : *files) {
            ui->failedFileList->addItem(QString::fromStdString(*(new std::string(filePath))));
        }
        if (mode == OperationMode::ENCRYPT && ui->randEncryptionKeyCheckBox->isChecked()) {
            for (const auto &filePath : *generatedKeys) {
                ui->generatedKeysList->addItem(QString::fromStdString(*(new std::string(filePath))));
            }
        } else {
            ui->keyFile->hide();
            ui->generatedKeysList->hide();
        }
        ui->cancelButton->setText("Exit");
        ui->loadingLabel->hide();
        ui->progressLabel->hide();
        currentGroupBox->i->t()->hide();
        (*currentGroupBox)++;
        currentGroupBox->i->t()->show();
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
    } else if (algorithm == EncryptionAlgorithm::GOST28147_89) {
        filter = "GOST28147_89 key (*.gostkey)";
    }
    QString filePath = QFileDialog::getOpenFileName(this, "Open file", "C://", filter, &filter);
    if (!filePath.isEmpty()) {
        keyFileLineEdit->clear();
        keyFileLineEdit->setText(filePath);
        ui->nextButton->setEnabled(true);
    }
}
