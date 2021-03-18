import java.math.BigInteger;
import java.util.Random;

public class testaes extends Parameters {
    public static final String DATA = "hi, welcome to my git area! aaddadadada";

    public static void main(String[] args) throws Exception {
        //获得密钥
        byte[] aesKey = AES.initKey();
        System.out.println(DATA.length());
        System.out.println(aesKey.length);
        System.out.println("AES 密钥 : " + BytesToHex.fromBytesToHex(aesKey));
        System.out.println("AES 密钥 ："+BytesToHex.fromBytesToHex(aesKey).length());
        //加密
        byte[] encrypt = AES.encryptAES(DATA.getBytes(), aesKey);
        System.out.println(DATA + " AES 加密 : " + BytesToHex.fromBytesToHex(encrypt).length());
        System.out.println(encrypt.length);

        //解密
        byte[] plain = AES.decryptAES(encrypt, aesKey);
        System.out.println(DATA + " AES 解密 : " + new String(plain).length());

        KeyGen();
        System.out.println(p);
        System.out.println(p.bitLength());
        System.out.println(p.toString().length());
        System.out.println(p.toString(16));
        System.out.println(p.toString(16).getBytes());
        System.out.println(BytesToHex.fromHexToBytes(p.toString(16)).length);
        System.out.println(aesKey.length);

    }
}
