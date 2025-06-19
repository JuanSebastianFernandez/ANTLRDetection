package com.vesta.test;
    import java.io.IOException;

    public class VulnerableApp {
        private String api_key = "ABC-123-SECRET"; // Hallazgo: Hardcoded Secret

        public void executeCommand(String command) {
            try {
                Runtime.getRuntime().exec(command); // Hallazgo: Dangerous Call
            } catch (IOException e) {
                // Hallazgo: Empty Catch Block
            }
        }
        
        public static void main(String[] args) {
             // Punto de entrada
        }
    }