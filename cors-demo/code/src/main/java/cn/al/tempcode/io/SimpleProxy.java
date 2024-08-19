package cn.al.tempcode.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SimpleProxy {

    public static void main(String[] args) throws IOException {
        final String localPort;
        final String remotePort;
        final String remoteHost;
        if (args.length != 3) {
            System.out.println("can't find local port ,remote server host ,and remote server port in args!\n");
            Scanner scanner = new Scanner(System.in);
            System.out.println("please input local port:\n");
            localPort = scanner.nextLine();
            System.out.println("please input remote server host:\n");
            remoteHost = scanner.nextLine();
            System.out.println("please input remote server port");
            remotePort = scanner.nextLine();
        } else {
            localPort = args[0];
            remoteHost = args[1];
            remotePort = args[2];
        }
        System.out.printf("*.*.*.*:%s -> %s:%s%n", localPort, remoteHost, remotePort);
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(localPort))) {
            while (true) {
                final Socket accept = serverSocket.accept();
                System.out.println("accepted connection from " + accept.getInetAddress());
                executorService.submit(() -> forwardData(accept, remoteHost, remotePort));
            }
        } finally {
            executorService.shutdown();
        }
    }

    public static void forwardData(Socket clientSocket, String remoteHost, String remotePort) {
        try (Socket remoteSocket = new Socket(remoteHost, Integer.parseInt(remotePort))) {
            Thread client2Server = new Thread(() -> transferBytes(clientSocket, remoteSocket), "client -> server");
            Thread server2Client = new Thread(() -> transferBytes(remoteSocket, clientSocket), "server -> client");
            client2Server.start();
            server2Client.start();
            client2Server.join();
            server2Client.join();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void transferBytes(Socket inSocket, Socket outSocket) {
        long start = System.currentTimeMillis();
        try (InputStream inputStream = inSocket.getInputStream();
             OutputStream outputStream = outSocket.getOutputStream()) {
            byte[] bytes = new byte[1024];
            int read;
            //120S超时
            while (System.currentTimeMillis() < start + 60 * 1000 * 2 && !inSocket.isClosed() && !outSocket.isClosed()) {
                read = inputStream.read(bytes);
                if (read != -1) {
                    start = System.currentTimeMillis();
                    outputStream.write(bytes, 0, read);
                    outputStream.flush();
                    System.out.println("Thread name: " + Thread.currentThread().getName() + " send: " + formatHexDump(bytes, 0, read));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String formatHexDump(byte[] data, int offset, int count) {
        StringBuilder sb = new StringBuilder();
        int rowLength = 16;
        for (int i = 0; i < count; i++) {
            sb.append(String.format("%02X", data[offset + i]));
            if (i % 4 == 3) {
                sb.append(' ');//四个字符 一个空格
            }
            //最后一行尾追加ascii 字符
            if (i == data.length - 1) {
                //先填充空格对齐
                for (int j = i + 1; j % rowLength != 0; j++) {
                    sb.append("  ");
                    if (j % 4 == 3) {
                        sb.append(' ');
                    }
                }
                //然后补充ascii字符
                sb.append(" ||  ");
                for (int cur = i - i % rowLength; cur <= i; cur++) {
                    char ch = (char) data[offset + cur];
                    sb.append(Character.isISOControl(ch) ? '.' : ch);
                }
                sb.append('\n');
            }
            //非最后一行 行尾添加ascii字符
            if (i % rowLength == rowLength - 1 && i != data.length - 1) {
                sb.append(" ||  ");
                for (int cur = i - rowLength - 1; cur <= i; cur++) {
                    char ch = (char) data[offset + cur];
                    sb.append(Character.isISOControl(ch) ? '.' : ch);
                }
                sb.append('\n');
            }
        }
        return sb.toString();
    }
}
