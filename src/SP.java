import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public  class SP {
    private static HashMap<String,ArrayList<String>>sp= new HashMap<>();
    private static ArrayList<String>array1;


    public static HashMap<String, ArrayList<String>> getSp() {
        return sp;
    }
    public static void setSp(String name,BigInteger ku,String EncRu,String Encvu){
        array1= new ArrayList<>();
        array1.add(ku.toString());
        array1.add(EncRu);
        array1.add(Encvu);
        sp.put(name,array1);
    }
    public static String getKu(String name) {
        return sp.get(name).get(0);
    }//十进制存放
    public static String getEncRu(String name){
        return sp.get(name).get(1);
    }//16进制存放
    public static String getEncvu(String name){
        return sp.get(name).get(2);
    }//16进制存放
}
