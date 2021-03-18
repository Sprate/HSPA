import org.apache.commons.codec.DecoderException;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Parameters {
    public static int qbits = 512;
    public static BigInteger q;
    public static BigInteger g;
    private static BigInteger seta;
    public static BigInteger u;
    public static BigInteger p;

    // q是阶 160bits g是生成元 1024bits p是循环群 1024bits
    public static void KeyGen() {
        q = new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5",16);
        g = new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",16);
        p = new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",16);
        seta = BigInteger.probablePrime(160, new Random()).mod(q);
        u = g.modPow(seta, p);
        System.out.println("Setup阶段完成");
        System.out.println("系统参数");
        System.out.println("q:  "+q);
        System.out.println("p   "+p);
        System.out.println("g   "+u);
    }
    public  static BigInteger get_seta()
    {
        return seta;
    }
    //hash函数是sha1 输出160位
    public static String getSha1(String str) {
        if (null == str || 0 == str.length()) {
            return null;
        }
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'a', 'b', 'c', 'd', 'e', 'f'};
        String buf = getString(str, hexDigits);
        if (buf != null) return buf;
        return null;
    }

    static String getString(String str, char[] hexDigits) {
        try {
            MessageDigest mdTemp = MessageDigest.getInstance("SHA1");
            mdTemp.update(str.getBytes("UTF-8"));

            byte[] md = mdTemp.digest();
            int j = md.length;
            char[] buf = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                buf[k++] = hexDigits[byte0 >>> 4 & 0xf];
                buf[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(buf);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }


}


