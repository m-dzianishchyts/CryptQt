#include "application.h"
#include "ui_application.h"

#include <QMessageBox>

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

    encryptionAlgorithm = new QString(ui->algorithmComboBox->currentText());
    mode = new QString(ui->modeComboBox->currentText());
}

Application::~Application() {
    delete ui;
}


void Application::on_backButton_clicked() {
    currentGroupBox->i->t()->hide();
    (*currentGroupBox)--;
    if (*currentGroupBox == stages.begin()) {
        ui->backButton->setEnabled(false);
    }
    currentGroupBox->i->t()->show();
}

void Application::on_nextButton_clicked() {
    currentGroupBox->i->t()->hide();
    (*currentGroupBox)++;
//    if (currentGroupBox->i->t() == ui->processingGroupBox) {
//        ui->nextButton->hide();
//        ui->backButton->hide();
//    }
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
    if (mode->compare(value) != 0) {
        ui->fileList->clear();
        *mode = value;
        if (mode->compare("Encrypt") == 0) {
            if (encryptionAlgorithm->compare("RC4") == 0) {
                ui->keyRC4LineEdit->clear();
                stages.replace(4, ui->keyRC4GroupBox);
            } else {
                stages.removeAt(4);
            }
        } else {
            if (encryptionAlgorithm->compare("RC4") == 0) {
                stages.replace(4, ui->keyGroupBox);
            } else {
                stages.insert(4, ui->keyGroupBox);
            }
        }
    }
}

void Application::on_algorithmComboBox_currentTextChanged(const QString &value) {
    QString oldAlgorithm = *encryptionAlgorithm;
    if (oldAlgorithm.compare(value) != 0) {
        ui->fileList->clear();
        *encryptionAlgorithm = value;
        if (mode->compare("Encrypt") == 0) {
            if (encryptionAlgorithm->compare("RC4") == 0) {
                ui->keyRC4LineEdit->clear();
                stages.insert(4, ui->keyRC4GroupBox);
            } else if (oldAlgorithm.compare("RC4") == 0) {
                stages.removeAt(4);
            }
        }
    }
}
