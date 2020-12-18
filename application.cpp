#include "application.h"
#include "ui_application.h"

#include <string>
#include <QMessageBox>
#include <QFileDialog>

Application::Application(QWidget *parent) : QMainWindow(parent), ui(new Ui::Application) {
    ui->setupUi(this);
    setMaximumSize(800, 600);
    setWindowIcon(QIcon("images/icon.ico"));

    for(auto groupBox : {ui->modeGroupBox, ui->algorithmGroupBox, ui->filesGroupBox,
                         ui->keyRC4GroupBox, ui->keyGroupBox, ui->processingGroupBox,
                         ui->completedGroupBox}) {
        groupBox->move(260, 0);
        groupBox->hide();
    }
    stages.append(ui->welcomeGroupBox);
    stages.append(ui->modeGroupBox);
    stages.append(ui->algorithmGroupBox);
    stages.append(ui->filesGroupBox);
    stages.append(ui->keyRC4GroupBox);
    stages.append(ui->processingGroupBox);
    stages.append(ui->completedGroupBox);
    currentGroupBox = new QList<QGroupBox*>::iterator(stages.begin());

    algorithm = algorithmValueOf(ui->algorithmComboBox->currentText().toStdString());
    mode = modeValueOf(ui->modeComboBox->currentText().toStdString());
}

Application::~Application() {
    delete ui;
}

void prepareForEncryption() {

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
        ui->nextButton->hide();
        ui->backButton->hide();
    }
    if ((currentGroupBox->i->t() == ui->filesGroupBox && ui->fileList->count() == 0)
            || (currentGroupBox->i->t() == ui->keyGroupBox && ui->keyLineEdit->text().isEmpty())
                || (currentGroupBox->i->t() == ui->keyRC4GroupBox && ui->keyRC4LineEdit->text().isEmpty())) {
        ui->nextButton->setEnabled(false);
    }
    if (currentGroupBox->i->t() == ui->processingGroupBox) {
        prepareForEncryption();
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
            if (algorithm == EncryptionAlgorithm::RC4) {
                ui->keyRC4LineEdit->clear();
                stages.replace(4, ui->keyRC4GroupBox);
            } else {
                stages.removeAt(4);
            }
        } else {
            ui->keyLineEdit->clear();
            if (algorithm == EncryptionAlgorithm::RC4) {
                stages.replace(4, ui->keyGroupBox);
            } else {
                stages.insert(4, ui->keyGroupBox);
            }
        }
    }
}

void Application::on_algorithmComboBox_currentTextChanged(const QString &value) {
    EncryptionAlgorithm oldAlgorithm = algorithm;
    EncryptionAlgorithm newAlgorithm = algorithmValueOf(value.toStdString());
    if (oldAlgorithm != newAlgorithm) {
        ui->fileList->clear();
        ui->keyLineEdit->clear();
        algorithm = newAlgorithm;
        if (mode == OperationMode::ENCRYPT) {
            if (algorithm == EncryptionAlgorithm::RC4) {
                ui->keyRC4LineEdit->clear();
                stages.insert(4, ui->keyRC4GroupBox);
            } else if (oldAlgorithm == EncryptionAlgorithm::RC4) {
                stages.removeAt(4);
            }
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

void Application::on_openKeyFileButton_clicked() {
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
        ui->keyLineEdit->clear();
        ui->keyLineEdit->setText(filePath);
        ui->nextButton->setEnabled(true);
    }
}

void Application::on_keyRC4LineEdit_textEdited(const QString &value) {
    ui->nextButton->setEnabled(!value.isEmpty());
}

void Application::on_randRC4keyCheckBox_stateChanged(int state) {
    ui->keyRC4LineEdit->setEnabled(!state);
    ui->nextButton->setEnabled(state || !ui->keyRC4LineEdit->text().isEmpty());
}
