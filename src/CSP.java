

import org.apache.commons.codec.DecoderException;
import sun.security.krb5.internal.crypto.Des;

import java.math.BigInteger;
import java.util.Random;

public class CSP extends Parameters {
    private static BigInteger IDcsp;
    private static BigInteger Rcsp;
    private static BigInteger vcsp;
    private static BigInteger Kcsp;
    private static BigInteger F;

    public static void CSPRegistration(){
      BigInteger[]skcsp= KGA.Regis(IDcsp);
      Rcsp=skcsp[0];
      vcsp=skcsp[1];
      System.out.println("CSP注册成功");
    }

    public static BigInteger getIDcsp() {
        return IDcsp;
    }

    public static BigInteger getVcsp() {
        return vcsp;
    }

    public static BigInteger getRcsp() {
        return Rcsp;
    }

    public static BigInteger getKcsp() {
        return Kcsp;
    }

    public static BigInteger getF() {
        return F;
    }

    public static void setF(BigInteger f) {
        F = f;
    }

    public static void setIDcsp(BigInteger IDcsp) {
        CSP.IDcsp = IDcsp;
    }

    public static void setKcsp(BigInteger kcsp) {
        Kcsp = kcsp;
    }

    public static BigInteger[] CSPAuthone(BigInteger X){
        long t=System.currentTimeMillis();
        BigInteger f=new BigInteger(160,new Random()).mod(q);
        BigInteger y=new BigInteger(160,new Random()).mod(q);
        BigInteger Y=g.modPow(y,p);
        BigInteger F=g.modPow(f,p);
        BigInteger Kcsp=X.modPow(y,p);
        setF(F);
        setKcsp(Kcsp);
        String Mcsp=getSha1(Kcsp.toString().concat(F.toString()));
        String Zcsp=getSha1(Mcsp.concat(getIDcsp().toString()).concat(F.toString()));//16进制字符串
        BigInteger Zcsp1=new BigInteger(Zcsp,16);
        BigInteger dcsp=(f.subtract(getVcsp().multiply(Zcsp1))).mod(q);
        BigInteger[]sigcsp=new BigInteger[4];
        sigcsp[0]=dcsp;
        sigcsp[1]=Zcsp1;
        sigcsp[2]=getRcsp();
        sigcsp[3]=Y;
        System.out.println("CSP 认证第一阶段时间为"+(System.currentTimeMillis()-t)+"ms");
        return sigcsp;
    }
    public static boolean CSPAuthtwo(String[]sigma) throws Exception {
        long t=System.currentTimeMillis();
        String EncKu_IDu=sigma[0];
        String EncKu_du =sigma[1];
        String EncKu_zu =sigma[2];
        String EncKu_Ru =sigma[3];

        String DecKcsp=getKcsp().toString(16).substring(0,32);
        byte[] DeC_Kcsp=BytesToHex.fromHexToBytes(DecKcsp);
        //System.out.println(DeC_Kcsp.length);

        long ttt=System.currentTimeMillis();
        String ID_u= BytesToHex.fromBytesToHex(AES.decryptAES(BytesToHex.fromHexToBytes(EncKu_IDu),DeC_Kcsp));
        String z_u=  BytesToHex.fromBytesToHex(AES.decryptAES(BytesToHex.fromHexToBytes(EncKu_zu),DeC_Kcsp));
        String d_u=  BytesToHex.fromBytesToHex(AES.decryptAES(BytesToHex.fromHexToBytes(EncKu_du),DeC_Kcsp));
        String R_u = BytesToHex.fromBytesToHex(AES.decryptAES(BytesToHex.fromHexToBytes(EncKu_Ru),DeC_Kcsp));
        System.out.println("CSP第二阶段AES"+(System.currentTimeMillis()-ttt)+"ms");

        BigInteger IDu=new BigInteger(ID_u,16);
        BigInteger zu=new BigInteger(z_u,16);
        BigInteger du=new BigInteger(d_u,16);
        BigInteger Ru=new BigInteger(R_u,16);
        /*System.out.println("auth2"+IDu);
        System.out.println("auth2"+zu);
        System.out.println("auth2"+du);
        System.out.println("auth2"+Ru);
        System.out.println(getKcsp());
        System.out.println(DecKcsp);
        System.out.println(EncKu_IDu);
        System.out.println(EncKu_Ru);
        System.out.println(EncKu_du);*/

        String w_u=getSha1(IDu.toString().concat(Ru.toString()));
        BigInteger wu=new BigInteger(w_u,16);

        BigInteger E1=g.modPow(du,p).multiply((Ru.multiply(u.modPow(wu,p))).modPow(zu,p)).mod(p);
        String Mu=getSha1(IDu.toString().concat(getKcsp().toString()).concat(getF().toString()));
        String zu1=getSha1(Mu.concat(IDu.toString()).concat(E1.toString()));
        boolean check2=zu.equals(new BigInteger(zu1,16));
        System.out.println("check2"+check2);
        System.out.println("CSP 认证第二阶段时间为"+(System.currentTimeMillis()-t)+"ms");
        return check2;
    }

}
