import java.math.BigInteger;
import java.util.Random;

public class KGA extends Parameters {


    public static BigInteger[] Regis(BigInteger IDu) {
        long t1=System.currentTimeMillis();
        BigInteger r_u = new BigInteger(160, new Random()).mod(q);
        BigInteger R_u = g.modPow(r_u, p);
        String IDRU = IDu.toString().concat(R_u.toString());
        BigInteger W_u = new BigInteger(getSha1(IDRU), 16);
        BigInteger V_u = r_u.add(get_seta().multiply(W_u)).mod(q);
        BigInteger[] sk_u = {R_u, V_u};
        System.out.println("ID:   "+IDu+"    注册成功");
        System.out.println("KGA注册时间为"+(System.currentTimeMillis()-t1)+"ms");
        System.out.println("R_u"+R_u);
        System.out.println("Vu"+V_u);
        return sk_u;
    }
}

