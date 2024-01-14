#include "mainwindow.h"
#include "networkinterface.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    nw =new networkinterface(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked(bool checked)
{
    //send signal to send message slot
    emit nw->Send_TCP();
    qDebug()<<"Send Button Pressed";
}

