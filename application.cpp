#include "application.h"
#include "ui_application.h"

Application::Application(QWidget *parent) : QMainWindow(parent), ui(new Ui::Application) {
    ui->setupUi(this);
    setMaximumSize(800, 600);

    for(auto groupBox : {ui->modeGroupBox, ui->algorithmGroupBox, ui->filesGroupBox,
                         ui->keyRC4GroupBox, ui->keyGroupBox, ui->processingGroupBox,
                         ui->completedGroupBox}) {
        groupBox->move(260, 0);
        groupBox->hide();
    }

    stages.append(ui->welcomeGroupBox);
    stages.append(ui->modeGroupBox);
    stages.append(ui->algorithmGroupBox);
    stages.append(ui->keyRC4GroupBox);
    stages.append(ui->processingGroupBox);
    stages.append(ui->completedGroupBox);
    currentGroupBox = new QList<QGroupBox*>::iterator(stages.begin());
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
    if (*currentGroupBox == stages.end() - 2) {
        ui->nextButton->hide();
        ui->backButton->hide();
    }
    currentGroupBox->i->t()->show();
    ui->backButton->setEnabled(true);
}
