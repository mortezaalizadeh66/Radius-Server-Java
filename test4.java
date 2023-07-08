import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class test4 {
    private static final String SHARED_SECRET = "Hello";

    public static void main(String[] args) throws Exception {
        System.out.println("RADIUS server started.");
        try {
            radius();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void radius() throws Exception {
        DatagramSocket serverSocket = null;

        try {
            serverSocket = new DatagramSocket(1812);
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }

        byte[] receiveBuffer = new byte[4096];
        String decryptedPasswordHex = "";
        byte[] data = null;
        while (true) {
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            serverSocket.receive(receivePacket);
            data = receivePacket.getData();
            int passwordOffset = getPasswordOffset(data);
            if (passwordOffset != -1) {
                byte[] passwordBytes = extractPasswordBytes(data, passwordOffset);
                byte[] requestAuthenticator = getRequestAuthenticator(data);

                byte[] S = SHARED_SECRET.getBytes();
                byte[] SRA = new byte[S.length + requestAuthenticator.length];
                System.arraycopy(S, 0, SRA, 0, S.length);
                System.arraycopy(requestAuthenticator, 0, SRA, S.length, requestAuthenticator.length);

                byte[] hashedPassword = md5(SRA);
                byte[] decryptedPassword = xorByteArrays(passwordBytes, hashedPassword);

                decryptedPasswordHex = byteArrayToHexString(decryptedPassword);
                System.out.println("Decrypted Password: " + decryptedPasswordHex);
            }

            byte[] response;
            if (decryptedPasswordHex.equals("6672616e313233210000000000000000")){

                response = createAccessAcceptPacket(data);
            } else {
                response = createAccessRejectPacket(data);
            }

            // Send the response back to the client
            DatagramPacket sendPacket = new DatagramPacket(response, response.length,
                    receivePacket.getAddress(), receivePacket.getPort());
            serverSocket.send(sendPacket);

        }
    }



    private static int getPasswordOffset(byte[] data) {
        for (int i = 0; i < data.length - 2; i++) {
            if (data[i] == 2 && data[i + 1] >= 18) {
                return i + 2;
            }
        }
        return -1;
    }

    private static byte[] extractPasswordBytes(byte[] data, int passwordOffset) {
        int passwordLength = data[passwordOffset - 1] - 2;
        byte[] passwordBytes = new byte[passwordLength];

        for (int i = 0; i < passwordLength; i++) {
            passwordBytes[i] = data[passwordOffset + i];
        }

        return passwordBytes;
    }

    private static byte[] getRequestAuthenticator(byte[] data) {
        byte[] requestAuthenticator = new byte[16];
        System.arraycopy(data, 4, requestAuthenticator, 0, 16);
        return requestAuthenticator;
    }

    public static byte[] md5(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] xorByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] createAccessAcceptPacket(byte[] receivedPacket) throws Exception {
        byte[] response = new byte[20];
        response[0] = 2; // Access Accept code
        response[1] = receivedPacket[1]; // Identifier
        response[2] = 0; // Length (high byte)
        response[3] = 20; // Length (low byte)

        // Generate Response Authenticator
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(response, 0, 4); // Code, Identifier, Length
        md.update(Arrays.copyOfRange(receivedPacket, 4, 20)); // Request Authenticator
        md.update(SHARED_SECRET.getBytes());
        byte[] responseAuthenticator = md.digest();
        System.arraycopy(responseAuthenticator, 0, response, 4, responseAuthenticator.length);

        return response;
    }

    public static byte[] createAccessRejectPacket(byte[] receivedPacket) throws Exception {
        byte[] response = new byte[20];
        response[0] = 3; // Access Reject code
        response[1] = receivedPacket[1]; // Identifier
        response[2] = 0; // Length (high byte)
        response[3] = 20; // Length (low byte)

        // Generate Response Authenticator
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(receivedPacket, 0, 4); // Code, Identifier, Length
        md.update(Arrays.copyOfRange(receivedPacket, 4, 20)); // Request Authenticator
        md.update(SHARED_SECRET.getBytes());
        byte[] responseAuthenticator = md.digest();
        System.arraycopy(responseAuthenticator, 0, response, 4, responseAuthenticator.length);

        return response;
    }

}
