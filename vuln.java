// vuln.java
import java.io.*;
import java.util.*;

public class Vuln {
    public static void runCmd(String input) throws Exception {
        // 命令执行
        Runtime.getRuntime().exec(input);
    }

    public static void readFile(String name) throws Exception {
        // 路径穿越
        File f = new File("/safe/dir/" + name);
        new FileInputStream(f);
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            runCmd(args[0]);
            readFile(args[0]);
        }
    }
}