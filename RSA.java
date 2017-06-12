import java.util.ArrayList;
import java.util.Arrays;
import java.lang.StringBuilder;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static java.lang.Integer.parseInt;

/**
 * 2 prime numbers p and q
 * n = p*q
 * phi = (p-1)*(q-1)
 * e = # relatively prime to d (z not evenly divisible by e)
 * public key: n & e
 * private key: n & d
 */


/*
Possibly map your alphabet to values 0 .. 25
by e.g. subtracting the ASCII value
of A from each ASCII encoded character.
Then encrypt the resulting number.
You can store the ciphertext as numbers separated by spaces.

****  A message that is about to be encrypted is treated
* as one large number
 */
public class RSA {

    static ArrayList<Integer> list = new ArrayList<>();
    static BigInteger p;
    static BigInteger q;
    static BigInteger n;
    static BigInteger phi;
    static BigInteger d;
    static int e;
    static BigInteger bigE;
    static int k = 16;
    static ArrayList<BigInteger> bigIntegers = new ArrayList<>();
    //k --> bit length of mod operation

    static final BigInteger one = new BigInteger("1");
    static SecureRandom rnd = new SecureRandom();
    static String values = "¥¥¥¥¥¥¥¥¥¥ ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-_=+{[}],:;\"'<>.`~|";

    public RSA(int keyLength) {


        //e values are Fermat's numbers
        this.k = keyLength;
        //p and q are random prime numbers of bit length k/2
        int[] eValues = {3, 5, 17, 257, 65537};

        this.bigE = new BigInteger("65537");

        this.p = generatePrime(keyLength/2, rnd);
        this.q = generatePrime(keyLength/2, rnd);

        while(p.compareTo(q) == 0)
        {
            this.p = generatePrime(keyLength/2, rnd);
            this.q = generatePrime(keyLength/2, rnd);
        }




        this.n = p.multiply(q);
        // phi = (p-1)*(q-1)
        this.phi = (p.subtract(one).multiply(q.subtract(one)));
        // ed mod phi = 1
        this.d = bigE.modInverse(phi);


    }
    public void calcD(BigInteger e, BigInteger phi)
    {
        setD((e.modInverse(phi)));
    }
    public void calcN(BigInteger p, BigInteger q)
    {
        setN((p.multiply(q)));
    }
    public void calcPhi(BigInteger p, BigInteger q)
    {
        setPhi((p.subtract(one).multiply(q.subtract(one))));
    }
    public void calcE(BigInteger d, BigInteger phi)
    {
        //
        BigInteger newE = d.modInverse(phi);
        setE(newE, "" + newE);
    }
    public BigInteger getPhi()
    {
        return this.phi;
    }
    public BigInteger getBigE()
    {
        return this.bigE;
    }

    public int getE()
    {
        return this.e;
    }

    public BigInteger getN()
    {
        return this.n;
    }

    public BigInteger getD()
    {
        return this.d;
    }

    public int getK(){return this.k;}


    public BigInteger getP()
    {
        return this.p;
    }

    public BigInteger getQ()
    {
        return this.q;
    }
    public void setK(int newK)
    {
        this.k = newK;
    }
    public void setQ(BigInteger q)
    {
        this.q = q;
    }
    public void setP(BigInteger P)
    {
        this.p = P;
    }
    public void setPhi(BigInteger phi)
    {
        this.phi = phi;
    }
    public void setN(BigInteger N)
    {
        this.n = N;
    }
    public void setE(BigInteger E, String e)
    {
        this.bigE = E;
        this.e = Integer.parseInt(e);
    }
    public void setD(BigInteger D)
    {
        this.d = D;
    }



    public static BigInteger generatePrime(int bitSize, SecureRandom random)
    {
        BigInteger temp = BigInteger.probablePrime(bitSize,random);
        while(!temp.isProbablePrime(15) && !temp.mod(bigE).equals(one))
        {

            temp = BigInteger.probablePrime(bitSize,rnd);
        }
        return temp;
    }


    public static BigInteger encode(char message, BigInteger n, BigInteger e)
    {
        // m^e mod n
        String asciiValue = "" + (int)message;
        BigInteger m = new BigInteger(asciiValue);


        return  m.modPow(e,n);








    }

    public static BigInteger encode(String message, BigInteger n, BigInteger e)
    {
        StringBuilder charValue = new StringBuilder(k);

        for(int i = 0; i<message.length();i++) {
            charValue.append(values.indexOf(message.charAt(i)));




        }
        BigInteger m = new BigInteger(charValue.toString());
        System.out.println(m);

        return m.modPow(bigE,n);
    }

    public static BigInteger decode(BigInteger cipher, BigInteger d, BigInteger n) {


        //StringBuilder decoded = new StringBuilder(100);

        // E = encrypted
        //  (c^d)%n


        return cipher.modPow(d,n);



    }

    public BigInteger callEncode(String message)
    {
        return encode(message,n,bigE);
    }
    public String callDecode(BigInteger decode)
    {
        StringBuilder result = new StringBuilder(getK()/16);
        String decoded = decode(decode,d,n).toString();
        for(int i = 0; i<decoded.length()-1;i+=2)
        {
            String sub = decoded.substring(i, i + 2);
            result.append(values.charAt(Integer.parseInt(sub)));

        }
        return result.toString();

    }


    public static void main(String[] args) {




    }
}

