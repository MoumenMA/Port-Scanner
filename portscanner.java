import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;

public class portscanner {
    private static final Map<Integer, Double> portProbabilities = new HashMap<>();
    private static final Set<Integer> scannedPorts = new HashSet<>();
    private static final List<Integer> defenderLog = new ArrayList<>();
    private static boolean blocked = false;
    private static final int DEFENDER_THRESHOLD = 10; // Defender blocks after 10 scans

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter IP address to scan: ");
        String ip = scanner.nextLine().trim();
        initializePortProbabilities();
        startScan(ip);
    }

    private static void initializePortProbabilities() {
        for (int i = 1; i <= 65535; i++) {
            portProbabilities.put(i, 0.01);
        }
        portProbabilities.put(21, 0.08);
        portProbabilities.put(22, 0.06);
        portProbabilities.put(23, 0.09);
        portProbabilities.put(80, 0.1);
        portProbabilities.put(443, 0.05);
        portProbabilities.put(3306, 0.07);
        portProbabilities.put(3389, 0.1);
    }

    private static void updateProbabilities(int port, boolean wasOpen) {
        double currentProb = portProbabilities.getOrDefault(port, 0.01);
        if (wasOpen) {
            portProbabilities.put(port, Math.min(1.0, currentProb + 0.02));
        } else {
            portProbabilities.put(port, Math.max(0.001, currentProb - 0.005));
        }
    }

    private static void startScan(String ip) {
        ExecutorService executor = Executors.newFixedThreadPool(100);
        List<Future<ScanResult>> futures = new ArrayList<>();

        List<Integer> portsToScan = new ArrayList<>(portProbabilities.keySet());
        portsToScan.sort((a, b) -> Double.compare(portProbabilities.get(b), portProbabilities.get(a)));

        int openPorts = 0;
        List<String> htmlReport = new ArrayList<>();
        htmlReport.add("<html><head><title>Scan Report</title></head><body><h1>Scan Report for " + ip + "</h1><ul>");

        for (int port : portsToScan) {
            if (blocked) break;

            Future<ScanResult> future = executor.submit(() -> scanPort(ip, port));
            try {
                ScanResult result = future.get();
                updateProbabilities(result.port, result.isOpen);
                logDefenderActivity(result.port);

                if (result.isOpen) {
                    openPorts++;
                    String line = "Port " + result.port + " is open. Banner: " + result.banner;
                    System.out.println(line);
                    htmlReport.add("<li><b>Port " + result.port + ":</b> Banner: " + result.banner + "</li>");
                }
            } catch (Exception ignored) {}
        }

        htmlReport.add("</ul><p>Total open ports: " + openPorts + "</p></body></html>");
        executor.shutdown();

        String reportPath = "scan_report.html";
        try (PrintWriter writer = new PrintWriter(reportPath)) {
            for (String line : htmlReport) writer.println(line);
        } catch (IOException e) {
            System.out.println("Error writing report.");
        }

        if (blocked) {
            System.out.println("\nScan blocked by defender! Too many suspicious scans detected.");
        }
        System.out.println("\nScan complete. Report generated: " + reportPath);
    }

    private static void logDefenderActivity(int port) {
        scannedPorts.add(port);
        defenderLog.add(port);
        if (defenderLog.size() > DEFENDER_THRESHOLD) {
            blocked = true;
        }
    }

    private static ScanResult scanPort(String ip, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), 200);
            socket.getOutputStream().write("\n".getBytes());
            byte[] buffer = new byte[1024];
            int read = socket.getInputStream().read(buffer);
            String banner = (read > 0) ? new String(buffer, 0, read).trim() : "";
            return new ScanResult(port, true, banner);
        } catch (IOException ex) {
            return new ScanResult(port, false, "");
        }
    }

    static class ScanResult {
        int port;
        boolean isOpen;
        String banner;

        public ScanResult(int port, boolean isOpen, String banner) {
            this.port = port;
            this.isOpen = isOpen;
            this.banner = banner;
        }
    }
}