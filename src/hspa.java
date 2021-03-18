import java.math.BigInteger;
import java.net.UnknownServiceException;
import java.util.Random;

public class hspa extends Parameters {
    public static void main(String[]args) throws Exception {
        Parameters.KeyGen();
        AES.initKey();

        long UserRegisStart=System.currentTimeMillis();
        User qhh=new User();
        qhh.setName("qianhaohao");
        qhh.setIDu(new BigInteger(32,new Random()));
        qhh.setPwd("qwerasdfzxcv1996");
        qhh.UserRegistration();
        long UserRegisEnd=System.currentTimeMillis();
        System.out.println("用户注册所用总时间为"+(UserRegisEnd-UserRegisStart)+"ms");

        long CSPRegisStart=System.currentTimeMillis();
        CSP.setIDcsp(new BigInteger(32,new Random()));
        CSP.CSPRegistration();
        long CSPRegisEnd=System.currentTimeMillis();
        System.out.println("CSP注册时间为"+(CSPRegisEnd-CSPRegisStart)+"ms");

        User auth=new User();
        auth.setPwd(qhh.getPwd());
        auth.setIDu(qhh.getIDu());
        auth.setName(qhh.getName());
        long AuthStart=System.currentTimeMillis();
        for(int i=0;i<1;i++) {
            boolean result = auth.Authentication();
            if (result) {
                System.out.println("accept");
            } else System.out.println("reject");
        }
        long AuthEnd=System.currentTimeMillis();
        System.out.println("用户认证所用的总时间为"+(AuthEnd-AuthStart)+"ms");
    }
}
