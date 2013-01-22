/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.proxy.afgh;

import nics.crypto.Tuple;
import it.unisa.dia.gas.jpbc.*;
/**
 *
 * @author david
 */
public class ProxyMain {

    static long cpuTime;
    static long time[] = new long[20];
    static int i = 0;
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {



        //java.security.

        cpuTime = System.nanoTime();

        // 80 bits seg: r = 160, q = 512
        // 128 bits seg: r = 256, q = 1536
        // 256 bits seg: r = 512, q = 7680

        int rBits = 256; //160;    // 20 bytes
        int qBits = 1536; //512;    // 64 bytes

        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);

        medirTiempoMicroSegundos();

//        // Secret keys
//
//        byte[] sk_a = AFGH.generateSecretKey(global).toBytes();
//
//        System.out.println(medirTiempo());
//
//        byte[] sk_b = AFGH.generateSecretKey(global).toBytes();
//
//        System.out.println(medirTiempo());
//
//        // Public keys
//
//        byte[] pk_a = AFGH.generatePublicKey(sk_a, global);
//
//        System.out.println(medirTiempo());
//
//        byte[] pk_b = AFGH.generatePublicKey(sk_b, global);
//
//        System.out.println(medirTiempo());
//
//        // Re-Encryption Key
//
//        byte[] rk_a_b = AFGH.generateReEncryptionKey(pk_b, sk_a, global);
//
//        System.out.println(medirTiempo());
//
//        String message = "David";
//        byte[] m = message.getBytes();
//
//        System.out.println(medirTiempo());
//
//        byte[] c_a = AFGH.secondLevelEncryption(m, pk_a, global);
//
//        System.out.println(medirTiempo());
//
//        String c_a_base64 = Base64.encodeBase64URLSafeString(c_a);
//        //System.out.println("c_a_base64 = " + c_a_base64);
//
//        System.out.println(medirTiempo());
//
//        String rk_base64 = Base64.encodeBase64URLSafeString(rk_a_b);
//        //System.out.println("rk_base64 = " + rk_base64);
//        System.out.println(medirTiempo());
//
//        byte[] c, rk;
//        rk = Base64.decodeBase64(rk_base64);
//
//        System.out.println(medirTiempo());
//
//        c = Base64.decodeBase64(c_a_base64);
//
//        System.out.println(medirTiempo());
//
//        byte[] c_b = AFGH.reEncryption(c, rk, global);
//        //System.out.println("cb: " + Arrays.toString(c_b));
//        System.out.println(medirTiempo());
//
//        String c_b_base64 = Base64.encodeBase64URLSafeString(c_b);
//        //System.out.println("c_b_base64 = " + c_b_base64);
//
//        System.out.println(medirTiempo());
//
//        c = Base64.decodeBase64(c_b_base64);
//
//        System.out.println(medirTiempo());
//
//        byte[] m2 = AFGH.firstLevelDecryption(c_b, sk_b, global);
//        //System.out.println("m2:" + new String(m2));
//
//        System.out.println(medirTiempo());
//
//        assert message.equals(new String(m2).trim());
//
//        System.out.println();
//        System.out.println(global.toBytes().length);
//        System.out.println(sk_a.length);
//        System.out.println(sk_b.length);
//        System.out.println(pk_a.length);
//        System.out.println(pk_b.length);
//        System.out.println(rk_a_b.length);
//        System.out.println(m.length);
//        System.out.println(c_a.length);
//        System.out.println(c_b.length);
//
//        //
//        Map<String, byte[]> map = new HashMap<String, byte[]>();
//        map.put("sk_a", sk_a);
//        map.put("sk_b", sk_b);
//        map.put("pk_a", pk_a);
//        map.put("pk_b", pk_b);
//        map.put("rk_a_b", rk_a_b);
//        map.put("global", global.toBytes());
//        map.put("c_a_base64", c_a_base64.getBytes());
//
//        ObjectOutputStream fos = new ObjectOutputStream(new FileOutputStream("/Users/david/Desktop/pre.object"));
//        fos.writeObject(map);
//        fos.close();
        //

        // Secret keys

        Element sk_a = AFGHProxyReEncryption.generateSecretKey(global);

        medirTiempoMicroSegundos();

        Element sk_b = AFGHProxyReEncryption.generateSecretKey(global);

        medirTiempoMicroSegundos();

        Element sk_b_inverse = sk_b.invert();

        medirTiempoMicroSegundos();

        // Public keys

        Element pk_a = AFGHProxyReEncryption.generatePublicKey(sk_a, global);

        medirTiempoMicroSegundos();

        Element pk_b = AFGHProxyReEncryption.generatePublicKey(sk_b, global);

        medirTiempoMicroSegundos();

        ElementPowPreProcessing pk_a_ppp = pk_a.pow();

        medirTiempoMicroSegundos();

        // Re-Encryption Key

        Element rk_a_b = AFGHProxyReEncryption.generateReEncryptionKey(pk_b, sk_a);

        medirTiempoMicroSegundos();

        String message = "12345678901234567890123456789012";
        Element m = AFGHProxyReEncryption.stringToElement(message, global.getG2());

        medirTiempoMicroSegundos();

        Tuple c_a = AFGHProxyReEncryption.secondLevelEncryption(m, pk_a_ppp, global);

        medirTiempoMicroSegundos();

        PairingPreProcessing e_ppp = global.getE().pairing(rk_a_b);

        medirTiempoMicroSegundos();

        Tuple c_b = AFGHProxyReEncryption.reEncryption(c_a, rk_a_b, e_ppp);

        medirTiempoMicroSegundos();

        Element m2 = AFGHProxyReEncryption.firstLevelDecryptionPreProcessing(c_b, sk_b_inverse, global);

        medirTiempoMicroSegundos();

        assert message.equals(new String(m2.toBytes()).trim());

        for(int j = 0; j < i; j++){
            System.out.println(time[j]);
        }

//        System.out.println("m string : " + message.getBytes().length);
//        System.out.println("m in G2 : " + m.toBytes().length);
//        System.out.println("c_a_1 in G2: " + c_a.get(1).toBytes().length);
//        System.out.println("c_a_2 in G1: " + c_a.get(2).toBytes().length);
//        System.out.println("c_b_1 in G2: " + c_b.get(1).toBytes().length);
//        System.out.println("c_b_2 in G2: " + c_b.get(2).toBytes().length);
//        System.out.println("m2 in G2 : " + m2.toBytes().length);
        //System.out.println(AFGH.elementToString(m2));

        //System.out.println(medirTiempo());

    }



    public static long medirTiempoMicroSegundos() {
        time[i] = (System.nanoTime() - cpuTime)/1000;
        i++;
        cpuTime = System.nanoTime();
        return time[i];
    }
}
