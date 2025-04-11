package org.example;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class AESInterface extends Application {

    private AES aes;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("AES Szyfrowanie / Deszyfrowanie");

        Label inputLabel = new Label("Tekst wejściowy:");
        TextArea inputTextArea = new TextArea();

        Label keyLabel = new Label("Klucz (hex, 32/48/64 znaki):");
        TextField keyField = new TextField();

        Button encryptButton = new Button("Szyfruj tekst");
        Button decryptButton = new Button("Deszyfruj tekst");
        Button encryptFileButton = new Button("Szyfruj plik");
        Button decryptFileButton = new Button("Deszyfruj plik");

        Label outputLabel = new Label("Wynik:");
        TextArea outputTextArea = new TextArea();
        outputTextArea.setEditable(false);

        encryptButton.setOnAction(_ -> {
            try {
                byte[] key = AES.parseKey(keyField.getText());
                aes = new AES(key);
                byte[] input = inputTextArea.getText().getBytes(StandardCharsets.UTF_8);
                byte[] output = aes.encryptMany(input);
                outputTextArea.setText(AES.bytesToHex(output));
            } catch (Exception ex) {
                outputTextArea.setText("Błąd: " + ex.getMessage());
            }
        });

        decryptButton.setOnAction(_ -> {
            try {
                String hexKey = keyField.getText().replaceAll("\\s+", "");
                byte[] key = AES.parseKey(hexKey);
                aes = new AES(key);

                String inputText = inputTextArea.getText().replaceAll("\\s+", "");
                if (!inputText.matches("[0-9a-fA-F]+") || inputText.length() % 32 != 0) {
                    outputTextArea.setText("Błąd: Nieprawidłowy tekst zaszyfrowany (musi być hex i długość podzielna przez 32).\n");
                    return;
                }

                byte[] input = AES.hexToBytes(inputText);
                byte[] output = aes.decryptMany(input);
                outputTextArea.setText(new String(output, StandardCharsets.UTF_8));
            } catch (Exception ex) {
                outputTextArea.setText("Błąd: " + ex.getMessage());
            }
        });

        encryptFileButton.setOnAction(_ -> {
            try {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Wybierz plik do zaszyfrowania");
                File inputFile = fileChooser.showOpenDialog(primaryStage);
                if (inputFile == null) return;

                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Zapisz plik zaszyfrowany");
                File outputFile = saveChooser.showSaveDialog(primaryStage);
                if (outputFile == null) return;

                byte[] fileData = Files.readAllBytes(inputFile.toPath());
                byte[] key = AES.parseKey(keyField.getText());
                aes = new AES(key);
                byte[] encrypted = aes.encryptMany(fileData);
                Files.write(outputFile.toPath(), encrypted);
                outputTextArea.setText("Plik zaszyfrowano pomyślnie.");
            } catch (Exception ex) {
                outputTextArea.setText("Błąd podczas szyfrowania pliku: " + ex.getMessage());
            }
        });

        decryptFileButton.setOnAction(_ -> {
            try {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Wybierz plik do odszyfrowania");
                File inputFile = fileChooser.showOpenDialog(primaryStage);
                if (inputFile == null) return;

                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Zapisz odszyfrowany plik");
                File outputFile = saveChooser.showSaveDialog(primaryStage);
                if (outputFile == null) return;

                byte[] fileData = Files.readAllBytes(inputFile.toPath());
                byte[] key = AES.parseKey(keyField.getText());
                aes = new AES(key);
                byte[] decrypted = aes.decryptMany(fileData);
                Files.write(outputFile.toPath(), decrypted);
                outputTextArea.setText("Plik odszyfrowano pomyślnie.");
            } catch (Exception ex) {
                outputTextArea.setText("Błąd podczas deszyfrowania pliku: " + ex.getMessage());
            }
        });

        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setHgap(10);
        grid.setVgap(10);

        grid.add(inputLabel, 0, 0);
        grid.add(inputTextArea, 0, 1, 3, 1);
        grid.add(keyLabel, 0, 2);
        grid.add(keyField, 0, 3, 3, 1);
        grid.add(encryptButton, 0, 4);
        grid.add(decryptButton, 1, 4);
        grid.add(encryptFileButton, 0, 5);
        grid.add(decryptFileButton, 1, 5);
        grid.add(outputLabel, 0, 6);
        grid.add(outputTextArea, 0, 7, 3, 1);

        Scene scene = new Scene(grid, 700, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }
}
