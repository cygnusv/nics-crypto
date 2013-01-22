/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.proxy.afgh;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import java.util.Arrays;
import nics.crypto.Tuple;

/**
 *
 * @author david
 */
public class AFGHProxyReEncryption {

    public static Element generateSecretKey(AFGHGlobalParameters global) {

        Field Zq = global.getZq();

        /*
         * KEY GENERATION
         */

        // sk = a \in Zq
        return Zq.newRandomElement().getImmutable();
    }

//    public static byte[] generateSecretKey(GlobalParameters global) {
//        return generateSecretKey(global).toBytes();
//    }
    public static Element generatePublicKey(Element sk, AFGHGlobalParameters global) {

        ElementPowPreProcessing g = global.getG_ppp();

        // pk = g^sk
        return g.powZn(sk).getImmutable();
    }

    public static byte[] generatePublicKey(byte[] sk_bytes, AFGHGlobalParameters global) {

        Element sk = bytesToElement(sk_bytes, global.getZq());

        return generatePublicKey(sk, global).toBytes();
    }

    public static Element generateReEncryptionKey(Element pk_b, Element sk_a) {

        /*
         * Re-Encryption Key Generation
         */

        // RK(a->b) = pk_b ^(1/sk_a) = g^(b/a)
        Element rk_a_b = pk_b.powZn(sk_a.invert());
        return rk_a_b.getImmutable();

    }

    public static byte[] generateReEncryptionKey(byte[] pk_bytes, byte[] sk_bytes, AFGHGlobalParameters global) {
        return generateReEncryptionKey(
                bytesToElement(pk_bytes, global.getG1()),
                bytesToElement(sk_bytes, global.getZq())).toBytes();
    }

    public static byte[] firstLevelEncryption(byte[] message, byte[] pk_a, AFGHGlobalParameters global) {

        Field G2 = global.getG2();
        Field G1 = global.getG1();

        // message = m \in G2
        Element m = bytesToElement(message, G2);

        // pk_a \in G1
        Element pk = bytesToElement(pk_a, G1);

        Tuple c = firstLevelEncryption(m, pk, global);

        return mergeByteArrays(c.get(1).toBytes(), c.get(2).toBytes());

    }

    public static Tuple firstLevelEncryption(Element m, Element pk_a, AFGHGlobalParameters global) {

        /*
         * First Level Encryption
         * c = (c1, c2)     c1, c2 \in G2
         *      c1 = Z^ak = e(g,g)^ak = e(g^a,g^k) = e(pk_a, g^k)
         *      c2 = m·Z^k
         */

        Field G2 = global.getG2();
        Field Zq = global.getZq();

        Pairing e = global.getE();

        Element Z = global.getZ();
        Element g = global.getG();

        // random k \in Zq
        Element k = Zq.newRandomElement().getImmutable();

        // g^k
        Element g_k = g.powZn(k);

        // c1 = Z^ak = e(g,g)^ak = e(g^a,g^k) = e(pk_a, g^k)
        Element c1 = e.pairing(pk_a, g_k);


        // c2 = m·Z^k
        Element c2 = m.mul(Z.powZn(k));


        // c = (c1, c2)

        Tuple c = new Tuple(c1, c2);

        return c;

    }

    public static byte[] secondLevelEncryption(byte[] message, byte[] pk_a, AFGHGlobalParameters global) {

        Field G2 = global.getG2();
        Field G1 = global.getG1();

        System.out.println(G2.getClass());

        System.out.println("G2: " + G2.getLengthInBytes());
        // message = m \in G2
        Element m = bytesToElement(message, G2);
//        System.out.println("M : " + Arrays.toString(m.toBytes()));
        // pk_a \in G1
        Element pk = bytesToElement(pk_a, G1);



        Tuple c = secondLevelEncryption(m, pk, global);



        return mergeByteArrays(c.get(1).toBytes(), c.get(2).toBytes());

    }

    public static Tuple secondLevelEncryption(Element m, Element pk_a, AFGHGlobalParameters global) {

        /*
         * Second Level Encryption
         * c = (c1, c2)     c1 \in G1, c2 \in G2
         *      c1 = g^ak = pk_a^k
         *      c2 = m·Z^k
         */

        //Field G2 = global.getG2();
        Field Zq = global.getZq();

        Pairing e = global.getE();

        Element Z = global.getZ();

        

        // random k \in Zq
        Element k = Zq.newRandomElement().getImmutable();
        //System.out.println("k = " + elementToString(k));

        // c1 = pk_a^k
        Element c1 = pk_a.powZn(k).getImmutable();


        // c2 = m·Z^k
        Element c2 = m.mul(Z.powZn(k)).getImmutable();

        

        // c = (c1, c2)
        Tuple c = new Tuple(c1, c2);

        return c;

    }


    public static Tuple secondLevelEncryption(Element m, ElementPowPreProcessing pk_a_PPP, AFGHGlobalParameters global) {

        /*
         * Second Level Encryption
         * c = (c1, c2)     c1 \in G1, c2 \in G2
         *      c1 = g^ak = pk_a^k
         *      c2 = m·Z^k
         */

        //Field G2 = global.getG2();
        Field Zq = global.getZq();

        Pairing e = global.getE();

        //Element Z = global.getZ();

        ElementPowPreProcessing Z_PPP = global.getZ_ppp();

        

        // random k \in Zq
        Element k = Zq.newRandomElement().getImmutable();
        //System.out.println("k = " + elementToString(k));

        // c1 = pk_a^k
        Element c1 = pk_a_PPP.powZn(k).getImmutable();


        // c2 = m·Z^k
        Element c2 = m.mul(Z_PPP.powZn(k)).getImmutable();

        

        // c = (c1, c2)
        Tuple c = new Tuple(c1, c2);

        return c;

    }

    public static Tuple reEncryption(Tuple c, Element rk, AFGHGlobalParameters global) {

        /*
         * Re-Encryption
         * c' = ( e(c1, rk) , c2)   \in G2 x G2
         */

        Pairing e = global.getE();



        return new Tuple(e.pairing(c.get(1), rk), c.get(2));

    }

     public static Tuple reEncryption(Tuple c, Element rk, PairingPreProcessing e_ppp) {

        /*
         * Re-Encryption
         * c' = ( e(c1, rk) , c2)   \in G2 x G2
         */

        return new Tuple(e_ppp.pairing(c.get(1)), c.get(2));

    }

    public static byte[] reEncryption(byte[] c, byte[] rk, AFGHGlobalParameters global) {
        //System.out.println("R: " + Arrays.toString(c));
        // c1 \in G1, c2 \in G2
        Field G1 = global.getG1();
        Field G2 = global.getG2();

        Element c1 = G1.newElement();
        int offset = bytesToElement(c, c1, 0);
        c1 = c1.getImmutable();

        Element c2 = G2.newElement();
        bytesToElement(c, c2, offset);
        c2 = c2.getImmutable();


        Tuple t = reEncryption(new Tuple(c1, c2), bytesToElement(rk, G1), global);

        return mergeByteArrays(t.get(1).toBytes(), t.get(2).toBytes());

    }

    public static Element firstLevelDecryption(Tuple c, Element sk, AFGHGlobalParameters global) {
        // c1, c2 \in G2
        Element alpha = c.get(1);
        Element beta = c.get(2);

        Element sk_inverse = sk.invert();

        Element m = beta.div(alpha.powZn(sk_inverse));

        return m;
    }

    public static Element firstLevelDecryptionPreProcessing(Tuple c, Element sk_inverse, AFGHGlobalParameters global) {
        // c1, c2 \in G2
        Element alpha = c.get(1);
        Element beta = c.get(2);

        Element m = beta.div(alpha.powZn(sk_inverse));

        return m;
    }

    public static byte[] firstLevelDecryption(byte[] b, byte[] sk, AFGHGlobalParameters global) {
        //System.out.println(Arrays.toString(b));

        // c1, c2 \in G2
        Field G2 = global.getG2();

        Element alpha = G2.newElement();
        int offset = bytesToElement(b, alpha, 0);
        alpha = alpha.getImmutable();

        Element beta = G2.newElement();
        bytesToElement(b, beta, offset);
        beta = beta.getImmutable();

        //System.out.println(Arrays.toString(beta.toBytes()));



        Element key = bytesToElement(sk, global.getZq());

//        key.invert();
//        System.out.println(Arrays.toString(key.invert().toBytes()));

        Element m = firstLevelDecryption(new Tuple(alpha, beta), key, global);

        return m.toBytes();
    }

    public static byte[] secondLevelDecryption(byte[] b, byte[] sk, AFGHGlobalParameters global) {
        // c1 \in G1, c2 \in G2
        Field G1 = global.getG1();
        Field G2 = global.getG2();

        Element alpha = G1.newElement();
        int offset = bytesToElement(b, alpha, 0);
        alpha = alpha.getImmutable();

        Element beta = G2.newElement();
        bytesToElement(b, beta, offset);
        beta = beta.getImmutable();

        Element key = bytesToElement(sk, global.getZq());


        Element m = secondLevelDecryption(new Tuple(alpha, beta), key, global);

        return m.toBytes();

    }

    public static Element secondLevelDecryption(Tuple c, Element sk, AFGHGlobalParameters global) {

        Element alpha = c.get(1);
        Element beta = c.get(2);

        Pairing e = global.getE();
        Element g = global.getG();

        Element m = beta.div(e.pairing(alpha, g).powZn(sk.invert()));

        return m;
    }

    public static Element decryption(Tuple c, Element sk, AFGHGlobalParameters global) {
        Field G2 = global.getG2();

        // if c1 \in G2 then First-Level
        if (c.get(1).getField().equals(G2)) {
            return firstLevelDecryption(c, sk, global);
        } else {
            return secondLevelDecryption(c, sk, global);
        }
    }

    public static Element stringToElement(String s, Field G) {
        //System.out.println(s + " = " + Arrays.toString(s.getBytes()));
        //return bytesToElement(Base64.decode(s), G);
        return bytesToElement(s.getBytes(), G);
    }

    public static Element bytesToElement(byte[] b, Field G) {
        int maxLengthBytes = G.getLengthInBytes();

        //System.out.println("maxLengthBytes = " + maxLengthBytes);
        if (b.length > maxLengthBytes) {
            throw new IllegalArgumentException("Input must be less than " + maxLengthBytes + " bytes");
        }
        //System.out.println(Arrays.asList(b));

        Element x = G.newElement();
        x.setFromBytes(b);

        //Element x = G.newElement(new BigInteger(1, b));
        return x.getImmutable();
    }

    public static int bytesToElement(byte[] b, Element x, int offset) {

        

        offset += x.setFromBytes(b, offset);

        return offset;
    }

    public static String elementToString(Element x) {
        //return Base64.encodeBytes(x.toBytes());
        return new String(x.toBytes()).trim();
    }

    public static byte[] mergeByteArrays(byte[]... bs) {
        int newLength = 0;
        for (byte[] b : bs) {
            newLength += b.length;
        }

        byte[] merge = new byte[newLength];

        int from = 0;
        for (byte[] b : bs) {
            System.arraycopy(b, 0, merge, from, b.length);
            from += b.length;
        }

        return merge;
    }
}
