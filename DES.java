/**
 * Created by tmoyer18 on 5/14/17.
 */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.lang.StringBuilder;
// ONLY operates on blocks of 64 bits
public class DES  {

    // test binary string: 0000000100100011010001010110011110001001101010111100110111101111
    //
    static final int[] PC1 = {57,49,41,33,25,17,9,1,58,50,42,
            34,26,18,10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4};
    static final int[] PC2 = {14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32};
    static final int[] IP = {58,50,42,34,    26 ,  18 ,   10 ,   2,
            60 ,   52,   44 ,   36 ,   28 ,  20 ,   12,    4,
            62 ,   54 ,  46 ,   38 ,   30 ,  22 ,   14 ,   6,
            64 ,   56,   48 ,   40,    32 ,  24 ,   16 ,   8,
            57 ,   49  , 41,    33 ,   25 ,  17 ,    9 ,   1,
            59  ,  51,   43 ,   35 ,   27  , 19   , 11 ,   3,
            61  ,  53 ,  45  ,  37 ,   29   ,21 ,   13 ,   5,
            63  ,  55 ,  47 ,   39 ,   31 ,  23 ,   15,    7};
    static final int[] ETable = {32  ,   1   , 2     ,3  ,   4 ,   5,
            4    , 5  ,  6    , 7 ,    8  ,  9,
            8   ,  9  , 10  ,  11 ,   12 ,  13,
            12  ,  13 ,  14 ,   15 ,   16 ,  17,
            16   , 17 ,  18 ,   19  ,  20,   21,
            20  ,  21 ,  22  ,  23  ,  24  , 25,
            24 ,   25,   26  ,  27 ,   28,  29,
            28 ,   29 ,  30 ,   31  ,  32  ,  1};
    static final int[][] s1 = {{14 , 4 , 13 , 1 ,  2 ,15  ,11  ,8  , 3 ,10   ,6 ,12 ,  5 , 9,   0 , 7},
            {0 ,15  , 7 , 4 , 14 , 2  ,13 , 1 , 10 , 6 , 12 ,11,   9 , 5,   3 , 8},
            {4 , 1 , 14 , 8  ,13 , 6 ,  2 ,11 , 15 ,12 ,  9  ,7,   3 ,10 ,  5 , 0},
            {15 ,12,   8  ,2  , 4 , 9 ,  1 , 7 ,  5, 11,   3 ,14 , 10,  0 ,  6 ,13}};
    static final int[][] s2 = {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
            {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,},
            {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
            {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};
    static final int[][] s3 = {
            {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
            {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
            {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
            {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};
    static final int[][] s4 = {
            {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
            {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
            {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};
    static final int[][] s5 = {
            {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
            {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
            {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
            {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};
    static final int[][] s6 = {
            {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
            {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
            {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
            {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};
    static final int[][] s7 = {
            {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
            {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
            {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
            {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};
    static final int[][] s8 = {
            {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
            {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
            {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
    static final int[][][] sTable = {s1,s2,s3,s4,s5,s6,s7,s8};
    static final int[] pTable = {16 ,  7,  20,  21,
            29,  12,  28 , 17,
            1 , 15,  23,  26,
            5  ,18  ,31 , 10,
            2  , 8,  24,  14,
            32  ,27  , 3 ,  9,
            19 , 13,  30,   6,
            22 , 11  , 4 , 25};
    static final int[] IPminusOne = {40  ,   8 ,  48,    16,    56 ,  24 ,   64 ,  32,
            39   ,  7  , 47   , 15  ,  55 ,  23   , 63  , 31,
            38    , 6  , 46  ,  14 ,   54 ,  22 ,   62,   30,
            37  ,   5 ,  45   , 13  ,  53 ,  21 ,   61  , 29,
            36   ,  4  , 44 ,   12  ,  52 ,  20 ,   60 ,  28,
            35  ,   3  , 43  ,  11   , 51  , 19   , 59  , 27,
            34   ,  2  , 42 ,   10,    50,   18 ,   58,   26,
            33   ,  1  , 41  ,   9  ,  49  , 17  ,  57  , 25};

    static final int[] leftShifts = {0,1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    static String baseKey = "";
    String[] cKeys = new String[16];
    String[] dKeys = new String[16];
    static String d0;
    static String c0;

    public DES()
    {

        this.baseKey = generateRandomBinaryString(64);


    }

    public String getKey()
    {
        return this.baseKey;
    }
    public void setKey(String key)
    {
        this.baseKey = key;
    }
    public  String generateRandomBinaryString(int bitNumber)
    {
        SecureRandom rnd = new SecureRandom();
        StringBuilder keyBuilding = new StringBuilder(bitNumber);
        String[] binaryDigits = {"0","1"};
        for(int bitIndex = 0; bitIndex<bitNumber;bitIndex++)
        {
            int digitToChoose = (int)Math.round(rnd.nextDouble());
            keyBuilding.append(binaryDigits[digitToChoose]);
        }

        return keyBuilding.toString();
    }
    public  String decimalto4DigitBinary(int value)
    {
        String result = "";
        int[] binaryPlaces = {8,4,2,1};
        for(int digitNum = 0;digitNum<4;digitNum++)
        {
            if(value / binaryPlaces[digitNum] == 1)
            {
                result+="1";
                value = value - binaryPlaces[digitNum];
            }
            else
            {
                result+="0";
            }

        }
        return result;
    }

    public static String hexToBinary(String hex)
    {
        String binary = "";

        for(int i = 0;i < hex.length(); i++)
        {
            char output = hex.charAt(i);


            if(output == '1')
                binary+="0001";
            else if(output == '0')
            {
                binary+="0000";
            }

            else if(output == '2')
                binary+="0010";
            else if(output == '3')
                binary+="0011";
            else if(output == '4')
                binary+="0100";
            else if(output == '5')
                binary+="0101";
            else if(output == '6')
                binary+="0110";
            else if(output == '7')
                binary+="0111";
            else if(output == '8')
                binary+="1000";
            else if(output == '9')
                binary+="1001";
            else if(output == 'a' ||output == 'A' )
                binary+="1010";
            else if(output == 'b' || output == 'B')
                binary+="1011";
            else if(output == 'c'|| output == 'C')
                binary+="1100";
            else if(output == 'd'|| output == 'D')
                binary+="1101";
            else if(output == 'e'|| output == 'E')
                binary+="1110";
            else if(output == 'f'|| output == 'F')
                binary+="1111";

        }




        return binary;
    }
    public  String[] removeNullAtEndAndAddToBeginning(String[] withNull)
    {
        //helper method to fix reversal of array
        String[] result = new String[withNull.length];
        result[0] = null;
        for(int i = 1; i<result.length;i++)
        {
            result[i] = withNull[i-1];
        }
        return result;
    }
    /*
    @param  binary
    @return array of split string
     */
    public  String[] reverseCombineBinaryArray(String[][] LnRnArray)
    {
        // Rn concat Ln
        String[] combined = new String[LnRnArray[0].length];

        for(int i = 0;i<LnRnArray[0].length;i++)
        {
            String Ln = LnRnArray[0][i];
            String rn = LnRnArray[1][i];
            combined[i] = rn+Ln;
        }
        return combined;
    }
    public   String[] splitBinary(String binary)
    {

        String[] splitString = new String[2];
        String left = "";
        String right = "";
        for(int posLeft = 0; posLeft<binary.length()/2;posLeft++)
        {
            left+=binary.charAt(posLeft);
        }
        for(int posRight = binary.length()-left.length();posRight<binary.length();posRight++)
        {
            right+=binary.charAt(posRight);
        }

        splitString[0] = left;
        splitString[1] = right;
        return splitString;
    }

    public  String permutateBasePC1(String base)
    {
        //defines initial permeated key
        System.out.println("base: " + base);
        String permutated = "";
        for(int i = 0; i<PC1.length;i++)
        {
            int index = PC1[i];
            permutated+=base.charAt(index-1);
        }
        return permutated;
    }
    public  String[] permutateBasePC2(String[] concatStrings)
    {
        // reduces size of concat keys to 48 bits
        String[] sixteenPerms = new String[concatStrings.length];
        for(int keyNumber = 1; keyNumber<concatStrings.length;keyNumber++)
        {
            String permutated = "";
            for(int i = 0;i< PC2.length;i++) {
                String temp = concatStrings[keyNumber];
                int index = PC2[i];
                permutated += temp.charAt(index - 1);
            }
            sixteenPerms[keyNumber] = permutated;
        }
        return sixteenPerms;
    }
    public  String[] flipArray(String[] notFlippedYet)
    {
        //flips key array for decryption
        String result[] = new String[notFlippedYet.length];
        int counter = 0;
        for(int i = notFlippedYet.length-1;i>=0;i--)
        {
            result[counter] = notFlippedYet[i];
            counter++;
        }
        return result;
    }
    public  String[][] create16KeysLeftShift(String cNot, String dNot)
    {
        //creates 16 keys by shifting previous key to the left by amount specified in table
        String[] sixteenKeysLeft = new String[17];
        sixteenKeysLeft[0] = cNot;
        String[] sixteenKeysRight = new String[17];

        String[][] result = {sixteenKeysLeft,sixteenKeysRight};

        sixteenKeysRight[0] = dNot;
        for(int keyNumberLeft = 1; keyNumberLeft<=16;keyNumberLeft++)
        {
            String prevKey = sixteenKeysLeft[keyNumberLeft-1];
            StringBuilder permKey = new StringBuilder(prevKey);


            for(int shifts = 0; shifts<leftShifts[keyNumberLeft];shifts++)
            {
                char firstChar = prevKey.charAt(0);
                for(int i = 0;i<prevKey.length()-1;i++)
                {
                    permKey.setCharAt(i,prevKey.charAt(i+1));
                }
                permKey.setCharAt(prevKey.length()-1,firstChar);
                prevKey = permKey.toString();
            }
            sixteenKeysLeft[keyNumberLeft] = prevKey;
        }
        for(int keyNumberRight = 1; keyNumberRight<=16;keyNumberRight++)
        {
            String prevKey = sixteenKeysRight[keyNumberRight-1];
            StringBuilder permKey = new StringBuilder(prevKey);


            for(int shifts = 0; shifts<leftShifts[keyNumberRight];shifts++)
            {
                char firstChar = prevKey.charAt(0);
                for(int i = 0;i<prevKey.length()-1;i++)
                {
                    permKey.setCharAt(i,prevKey.charAt(i+1));
                }
                permKey.setCharAt(prevKey.length()-1,firstChar);
                prevKey = permKey.toString();
            }
            sixteenKeysRight[keyNumberRight] = prevKey;
        }
        return result;
    }

    public static String binaryToHex (String binary1)
    {
        String quad = "";
        int charOne = 0;
        int charTwo = 0;
        int charThree = 0;
        int charFour = 0;
        char hexDigit = 'O';
        String hexResult = "";
        for(int x = 0; x<binary1.length(); x+=4)
        {
            quad = binary1.substring(x,x+4);
            //System.out.println(quad);
            if(quad.equals("0000"))
                hexDigit = '0';
            else if (quad.equals( "0001"))
                hexDigit = '1';
            else if(quad.equals( "0010"))
                hexDigit = '2';
            else if(quad.equals( "0100"))
                hexDigit = '4';
            else if(quad.equals( "1000"))
                hexDigit = '8';
            else if(quad.equals( "0011"))
                hexDigit = '3';
            else if(quad.equals( "0101"))
                hexDigit = '5';
            else if(quad.equals( "1001"))
                hexDigit = '9';
            else if(quad.equals( "0111"))
                hexDigit = '7';
            else if(quad.equals( "1011"))
                hexDigit = 'b';
            else if(quad.equals( "1111"))
                hexDigit = 'f';
            else if(quad.equals( "1110"))
                hexDigit = 'e';
            else if(quad.equals( "1101"))
                hexDigit = 'd';
            else if(quad.equals( "0110"))
                hexDigit = '6';
            else if(quad.equals( "1010"))
                hexDigit = 'a';
            else if(quad.equals( "1100"))
                hexDigit = 'c';
            hexResult+=hexDigit;

        }
        return hexResult;
    }
    public  String[][] calcLnRnArray(String initialLNot, String initialRNot,String[] keys) {

        String[] initialLPerms = new String[17];
        String[] initialRPerms = new String[17];

        //Ln = Rn-1
        //Rn = Ln-1 + f(Rn-1+Kn) (+ bitwise xor)
        initialLPerms[0] = initialLNot;
        initialRPerms[0] = initialRNot;
        String[][] LnRnPerms = new String[2][];
        // expanded Rn-1 XOR Kn

        for(int n = 1;n<initialLPerms.length;n++)
        {
            String Ln = initialRPerms[n-1];
            initialLPerms[n] = Ln;
            String Rn = calcR(initialRPerms[n-1],keys[n],initialLPerms[n-1]);
            initialRPerms[n] = Rn;

        }
        LnRnPerms[0] = initialLPerms;
        LnRnPerms[1] = initialRPerms;
        return LnRnPerms;
    }
    public  String calcR(String Rnminusone, String kn, String Lnminusone)
    {
        // Rn = Ln-1 + f(Rn-1,Kn)
        String rExpanded = eExpansion(Rnminusone);
        String xor = xorBinary(rExpanded,kn);
        String sExpanded = sBoxExpansion(xor);
        String R = xorBinary(sExpanded,Lnminusone);
        return R;

    }

    public  String xorBinary(String rnminusone, String nKey)
    {
        // XOR's two binary strings
        String xorResult = "";
        for (int i = 0; i < rnminusone.length(); i++) {
            int xOr = (Integer.parseInt(""+rnminusone.charAt(i),2 )) ^ (Integer.parseInt("" +nKey.charAt(i)));
            xorResult+=("" + xOr);
        }

        return xorResult;
    }

    public  String eExpansion(String gonnaPerm)
    {
        // expand Rn-1
        String result = "";

        for(int i = 0; i<ETable.length;i++)
        {
            result+=gonnaPerm.charAt(ETable[i]-1);
        }
        return result;
    }


    /*
    @param Kn XOR Rn-1
     */
    public  String sBoxExpansion(String xorString) {

        String[] splitUp = new String[8];
        String sResult = "";
        String[] sExpanded = new String[8];
        //loop over xor string and divide it into 8 groups of 6 and put them in array
        for (int b = 0; b < xorString.length(); b+=6) //b = box num
        {
            String sub = xorString.substring(b,b+6);
            splitUp[b/6] = sub;
        }
        // i = first and last bit of 6 bit binary digit (value is between 0 and 3)
        // j = middle 4 binary digits (value is between 0 and 15)
        for(int element = 0; element<splitUp.length;element++)
        {
            String iString = "" + splitUp[element].charAt(0) +splitUp[element].charAt(splitUp[element].length()-1);
            int i = Integer.parseInt(iString,2);
            String jString = splitUp[element].substring(1,splitUp[element].length()-1);
            int j = Integer.parseInt(jString,2);

            int[][] currentTable = sTable[element];
            int value = currentTable[i][j]; //this is the 4 bit binary digit that replaces the 6 bit digit
            splitUp[element] = decimalto4DigitBinary(value);
            sResult+=splitUp[element];

        }
        return pExpansion(sResult);

    }

    public  String ipminusonePerm(String R16L16)


    {

        //final expansion of R16L16 after XOR and f function expansion
        String result = "";
        for(int index = 0;index<IPminusOne.length;index++)
        {
            result+=R16L16.charAt(IPminusOne[index]-1);
        }
        return result;
    }
    public  String initialPerm(String message)
    {
        // expand initial binary string according to IP table
        String result = "";
        for(int i = 0; i<IP.length;i++)
        {
            int index = IP[i];
            result+= message.charAt(index-1);
        }
        return result;
    }
    public  String[] concactCD(String[]cKeys,String[] dKeys)
    {
        // concat left and right keys
        String[] concat = new String[cKeys.length];

        for(int i = 1; i<cKeys.length;i++)
        {
            String combined = cKeys[i] + dKeys[i];
            concat[i] = combined;
        }
        return concat;
    }

    public  String pExpansion(String expandThis)
    {
        // expand s-boxing according to P-Table
        String result = "";

        for(int index = 0;index<pTable.length;index++)
        {
            result+=expandThis.charAt(pTable[index] - 1);
        }
        return result;
    }
    public  String encryptBlock (String baseKey, String binaryMessage)
    {
        String k = permutateBasePC1(baseKey);
        String[] split = splitBinary(k);
        c0 = split[0];
        d0 = split[1];

        String[][] result = create16KeysLeftShift(c0,d0);
        String[] concat = concactCD(result[0],result[1]);
        String[] PC2Perm = permutateBasePC2(concat);
        String initialPerm = initialPerm(binaryMessage);
        String[] intialSplit = splitBinary(initialPerm);
        String initialLNot = intialSplit[0];
        String initialRNot = intialSplit[1];
        String[][] LnRnPerms = calcLnRnArray(initialLNot,initialRNot,PC2Perm);
        String[] reversed = reverseCombineBinaryArray(LnRnPerms);
        String encoded = ipminusonePerm(reversed[16]);
        return encoded;
    }

    public  String decryptBlock (String baseKey, String encodedMessage)
    {
        // same as encryption, but go from k16 to k0 instead of k0 to k16
        // literally do the same thing except flip the array of keys and do right shifts instead of left shifts
        //need to alter 16 keys method
        String k = permutateBasePC1(baseKey);
        String[] split = splitBinary(k);
        c0 = split[0];
        d0 = split[1];

        String[][] result = create16KeysLeftShift(c0,d0);
        String[] concat = concactCD(result[0],result[1]);

        String[] keys = permutateBasePC2(concat);

        String [] flippedKeys = removeNullAtEndAndAddToBeginning(flipArray(keys));



        String initialPerm = initialPerm(encodedMessage);
        String[] intialSplit = splitBinary(initialPerm);
        String initialLNot = intialSplit[0];
        String initialRNot = intialSplit[1];
        String[][] LnRnPerms = calcLnRnArray(initialLNot,initialRNot,flippedKeys);
        String[] reversed = reverseCombineBinaryArray(LnRnPerms);
        String encoded = ipminusonePerm(reversed[16]);
        return encoded;

    }


    public String encrypt(String encryptThis, String key)
    {
        String largeBinaryString = hexToBinary(encryptThis);
        StringBuilder encrypted = new StringBuilder(largeBinaryString.length());

        int amountOfBlocks = largeBinaryString.length()/64;

        for(int blockNum = 0; blockNum<amountOfBlocks; blockNum++)
        {
            String currentBlock = largeBinaryString.substring(blockNum*64,(64+(blockNum*64)));
            encrypted.append(encryptBlock(key, currentBlock));

        }
        return binaryToHex(encrypted.toString());
    }

    public String decryptBinary(String largeEncryptedBinaryString, String binaryKey)
    {
        StringBuilder decrypted = new StringBuilder(largeEncryptedBinaryString.length());
        int amountOfBlocks = largeEncryptedBinaryString.length()/64;

        for(int blockNum = 0; blockNum<amountOfBlocks; blockNum++)
        {
            String currentBlock = largeEncryptedBinaryString.substring(blockNum*64,(64+(blockNum*64)));
            decrypted.append(decryptBlock(binaryKey, currentBlock));

        }
        String decryptedString = decrypted.toString();
        return decryptedString;
    }


    public String decrypt(String hexString, String key)
    {
        String largeEncryptedBinaryString = hexToBinary(hexString);
        String binaryKey = hexToBinary(key);
        StringBuilder decrypted = new StringBuilder(largeEncryptedBinaryString.length());
        int amountOfBlocks = largeEncryptedBinaryString.length()/64;

        for(int blockNum = 0; blockNum<amountOfBlocks; blockNum++)
        {
            String currentBlock = largeEncryptedBinaryString.substring(blockNum*64,(64+(blockNum*64)));
            decrypted.append(decryptBlock(binaryKey, currentBlock));

        }
        String decryptedString = decrypted.toString();
        return binaryToHex(decryptedString);
    }



    public static void main(String[] args)
    {




    }

}
