package com.example.intrusiondetectionsystem;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.util.List;

public class Main extends Application {

    private TextArea txtReport;
    private Label lblStatus;

    @Override
    public void start(Stage primaryStage) {

        // 1. UI COMPONENTS
        Label lblTitle = new Label("🛡️ Intrusion Detection System (IDS)");
        lblTitle.setStyle("-fx-font-size: 18px; -fx-font-weight: bold;");

        Button btnLoad = new Button("📂 Load Server Log");
        btnLoad.setMaxWidth(Double.MAX_VALUE);

        lblStatus = new Label("Status: Waiting for log file...");
        lblStatus.setStyle("-fx-text-fill: grey;");

        txtReport = new TextArea();
        txtReport.setEditable(false);
        txtReport.setPrefHeight(400);
        txtReport.setStyle("-fx-font-family: 'Consolas', monospace;"); // Look like a terminal

        // 2. BUTTON LOGIC
        btnLoad.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select Server Log");
            // Set filter to only show .log or .txt files
            fileChooser.getExtensionFilters().add(
                    new FileChooser.ExtensionFilter("Log Files", "*.log", "*.txt")
            );

            File selectedFile = fileChooser.showOpenDialog(primaryStage);

            if (selectedFile != null) {
                lblStatus.setText("Analyzing: " + selectedFile.getName());
                performScan(selectedFile);
            }
        });

        // 3. LAYOUT
        VBox layout = new VBox(10);
        layout.setPadding(new Insets(20));
        layout.getChildren().addAll(lblTitle, btnLoad, lblStatus, new Separator(), new Label("Security Report:"), txtReport);

        Scene scene = new Scene(layout, 500, 600);
        primaryStage.setTitle("Java Blue Team IDS");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void performScan(File file) {
        // Run the analysis
        List<String> results = LogAnalyzer.analyzeLog(file);

        // Display results
        txtReport.clear();
        for (String alert : results) {
            txtReport.appendText(alert + "\n\n");
        }

        if (results.get(0).startsWith("✅")) {
            lblStatus.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");
            lblStatus.setText("Scan Complete: Clean");
        } else {
            lblStatus.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
            lblStatus.setText("Scan Complete: THREATS DETECTED");
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}