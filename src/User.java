import com.sun.xml.internal.bind.v2.model.core.ID;
import org.apache.commons.codec.DecoderException;

import java.math.BigInteger;
import java.sql.SQLOutput;
import java.util.Random;

public class User extends Parameters {
   private BigInteger IDu;//32bits
   private String name;//
   private String pwd;//16位字符串
  // private BigInteger k_u;//160bits
  // private String rwd;//rwd 是hash后的输出，为160bits 取它的前128bits作为对称密钥
  // private BigInteger[]sku;
  // private BigInteger R_u;//1024bits
  // private BigInteger v_u;//160bits
  // private String c_u_0;
   //private String c_u_1;//对称加密后分两个Ru和vu，每个都是byte型数组，转为16进制字符串输出


   public User() {
   }

   public void setName(String Name){
      this.name=Name;
   }
   public void setIDu(BigInteger idu){
      this.IDu=idu;

   }
   public void setPwd(String password){
      this.pwd=password;
   }

   public String getName() {
      return name;
   }

   public BigInteger getIDu() {
      return IDu;
   }

   public String getPwd() {
      return pwd;
   }

   public void UserRegistration() throws Exception {
      BigInteger[]sku=KGA.Regis(IDu);
      System.out.println("用户"+getName()+"获取sku成功");

      long t1=System.currentTimeMillis();
      BigInteger R_u=sku[0];
      BigInteger v_u=sku[1];
      BigInteger k_u=new BigInteger(160,new Random()).mod(q);
      BigInteger H1pwd=new BigInteger(getSha1(getPwd()),16);
      String H1=H1pwd.modPow(k_u,p).toString();
      String rwd=getSha1(getPwd().concat(H1));
      String EncRwd=rwd.substring(0,32);
      byte[]Enc_Rwd =BytesToHex.fromHexToBytes(EncRwd);
      //System.out.println(Enc_Rwd.length);
      //System.out.println(R_u);
      //System.out.println(R_u.toString(16)
      long aes=System.currentTimeMillis();
      System.out.println("aes之前"+(System.currentTimeMillis()-t1)+"ms");
      String c_u_0=BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(R_u.toString(16)),Enc_Rwd));
      String c_u_1=BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(v_u.toString(16)),Enc_Rwd));
      System.out.println("AES   "+(System.currentTimeMillis()-aes)+"ms");

      //c_u[0]=BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(R_u.toString(16)),Enc_Rwd));
      //c_u[1]=BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(v_u.toString(16)),Enc_Rwd));
      //System.out.println("对称加密Ru后的16进制长度为"+c_u_0.length());
      System.out.println(c_u_0.length());
      System.out.println(c_u_1.length()+"13213463464");
     // System.out.println("对称加密vu后的16进制长度为"+c_u_1.length());
      System.out.println("用户注册user端时间"+(System.currentTimeMillis()-t1)+"ms");
      SendRegis(getName(),k_u,c_u_0,c_u_1);
      System.out.println("用户注册阶段完成");
   }
   public void SendRegis(String name,BigInteger k_u,String c_u_0,String c_u_1){
      SP.setSp(name,k_u,c_u_0,c_u_1);
      System.out.println(name+"存储到SP成功");
   }
   public Boolean Authentication() throws Exception {
      long AuthStart=System.currentTimeMillis();
      BigInteger a=new BigInteger(160,new Random()).mod(q);
      String alpha=new BigInteger(getSha1(getPwd()),16).modPow(a,p).toString();//10进制字符串
      System.out.println("alpha         "+new BigInteger(alpha).bitLength());

      long tsp=System.currentTimeMillis();
      String[]ret=UserRetrieve(alpha,getName());
      System.out.println("SP retrieve时间为"+(System.currentTimeMillis()-tsp)+"ms");

      BigInteger beta=new BigInteger(ret[0]);
      String EncRu=ret[1];
      String Encvu=ret[2];

      BigInteger ku= new BigInteger(SP.getKu(getName()));
      BigInteger H1pwd=new BigInteger(getSha1(getPwd()),16);
      String H1=H1pwd.modPow(ku,p).toString();
      String rwd1=getSha1(getPwd().concat(H1));

      BigInteger e=new BigInteger(160,new Random()).mod(q);
      BigInteger x=new BigInteger(160,new Random()).mod(q);
      BigInteger E=g.modPow(e,p);
      BigInteger X=g.modPow(x,p);
      System.out.println("e  "+e);
      long t1=System.currentTimeMillis()-AuthStart;
      System.out.println("用户认证 user端第一阶段时间为"+t1+"ms");

      BigInteger[] sig_csp= CSP.CSPAuthone(X);
      //接收sig_csp和Y
      long t2=System.currentTimeMillis();
      BigInteger Y=sig_csp[3];
      BigInteger dcsp=sig_csp[0];
      BigInteger Zcsp=sig_csp[1];
      BigInteger Rcsp=sig_csp[2];

      BigInteger Ku=Y.modPow(x,p);
      String wcsp=getSha1(CSP.getIDcsp().toString().concat(Rcsp.toString()));
      BigInteger wcsp1=new BigInteger(wcsp,16);
      BigInteger F1=g.modPow(dcsp,p).multiply((Rcsp.multiply(u.modPow(wcsp1,p))).modPow(Zcsp,p)).mod(p);
      String Mcsp=getSha1(Ku.toString().concat(F1.toString()));
      String Zcsp1=getSha1(Mcsp.concat(CSP.getIDcsp().toString()).concat(F1.toString()));
      Boolean check1=Zcsp.equals(new BigInteger(Zcsp1,16));

      System.out.println("check1结果为"+check1);

      if (check1)
      { //AES解密
         String DecRwd=rwd1.substring(0,32);
         byte[]Dec_Rwd =BytesToHex.fromHexToBytes(DecRwd);
         String R_u= BytesToHex.fromBytesToHex(AES.decryptAES(BytesToHex.fromHexToBytes(EncRu),Dec_Rwd));
         String v_u= BytesToHex.fromBytesToHex(AES.decryptAES(BytesToHex.fromHexToBytes(Encvu),Dec_Rwd));
         BigInteger Ru=new BigInteger(R_u,16);
         BigInteger vu=new BigInteger(v_u,16);

         String Mu=getSha1(getIDu().toString().concat(Ku.toString()).concat(F1.toString()));//16进制
         String z_u=getSha1(Mu.concat(getIDu().toString()).concat(E.toString()));
         BigInteger zu=new BigInteger(z_u,16);

         BigInteger du=e.subtract(vu.multiply(zu)).mod(q);
         String EncKu=Ku.toString(16).substring(0,32);
         byte[]Enc_Ku=BytesToHex.fromHexToBytes(EncKu);
         long tt=System.currentTimeMillis();
         String EncKu_IDu= BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(getIDu().toString(16)),Enc_Ku));
         String EncKu_zu=  BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(zu.toString(16)),Enc_Ku));
         String EncKu_du=  BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(du.toString(16)),Enc_Ku));
         String EncKu_Ru = BytesToHex.fromBytesToHex(AES.encryptAES(BytesToHex.fromHexToBytes(Ru.toString(16)),Enc_Ku));
         System.out.println("user 第二阶段aes"+(System.currentTimeMillis()-tt)+"ms");
         System.out.println("sigma -----------------");
         System.out.println("IDu "+(EncKu_IDu.length()*4));
         System.out.println("zu  "+(EncKu_zu.length()*4));
         System.out.println("du  "+(EncKu_du.length()*4));
         System.out.println("Ru  "+(EncKu_Ru.length()*4));

         String[]sigma=new String[5];//16进制sigma字符串
         sigma[0]=EncKu_IDu;
         sigma[1]=EncKu_du;
         sigma[2]=EncKu_zu;
         sigma[3]=EncKu_Ru;
         /*System.out.println("User");
         System.out.println(IDu);
         System.out.println(du);
         System.out.println(zu);
         System.out.println(Ru);
         System.out.println("Ku"+Ku);
         System.out.println(EncKu);
         System.out.println(EncKu_IDu);
         System.out.println(EncKu_Ru);*/
         long t3=System.currentTimeMillis()-t2;
         System.out.println("用户认证 user端第二阶段时间为"+t3+"ms");
         System.out.println("用户认证 user端总时间为"+(t3+t1)+"ms");
         boolean check2= CSP.CSPAuthtwo(sigma);
         return check2;
      }
      else return false;


   }
   public String[] UserRetrieve(String alpha,String name){

      BigInteger k_u=new BigInteger(SP.getKu(name));
      BigInteger Beta=new BigInteger(alpha).modPow(k_u,p);
      String []retri=new String[3];
      retri[0]=Beta.toString();//10进制存放字符串
      retri[1]=SP.getEncRu(name);//16进制
      retri[2]= SP.getEncvu(name);//16进制
      return retri;

   }

}
