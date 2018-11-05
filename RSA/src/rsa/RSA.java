package rsa;

import java.util.Scanner;
import java.security.SecureRandom;

public class RSA{
    static boolean debug_numbers = false;  // Show generated values
    static boolean debug_encryption = false;  // Show encryption process
    
    public static void main(String[] args){
        rsa();
    }
    
    public static void rsa(){
        int bitLength = 256;
        int variance = 32;
        
        BigInt[] keys = getKeys(bitLength, variance);
        BigInt e = keys[0];
        BigInt d = keys[1];
        BigInt n = keys[2];
        
        System.out.printf("Using %d-bit keys ± %d bits\n\n", bitLength, variance);
        
        Scanner kb = new Scanner(System.in);
        System.out.print("Enter message: ");
        String m = kb.nextLine();
        
        String cipher = encrypt(m, d, n);
        System.out.printf("Encryption: %s\n", cipher);
        
        String decipher = decrypt(cipher, e, n);
        System.out.printf("Decryption: %s\n", decipher);
    }
    
    /**
     * Generates 2 keys and a world to be used in an RSA encryption algorithm.
     * 
     * @param bits      The bit length used to generate each prime number.
     *                  Actual length varies according to the next parameter.
     * @param var       The range above or below the bit-length from which
     *                  they keys may be generated.
     * @return          An array of 3 BigInts - [decrypt key, encrypt key
     *                  world]
     */
    public static BigInt[] getKeys(int bits, int var){
        if (bits < 8){  // split() uses byte length minus 1, cannot be 0
            System.out.print("Minimum bit-length of 8 required\n");
            System.out.print("Setting bit-length to 8\n\n");
            bits = 8;
        }
        
        SecureRandom rnd = new SecureRandom();
        BigInt p;  // Prime 01
        BigInt q;  // Prime 02
        
        while (true){
            // p and q bit-length differences
            int x = (var > 0 ? rnd.nextInt(2*var) - var : 0);
            int y = (var > 0 ? rnd.nextInt(2*var) - var : 0);
            
            p = BigInt.probablePrime(bits + x, rnd);
            q = BigInt.probablePrime(bits + y, rnd);
            
            if (!p.equals(q))  
                break;  // Primes are valid
        }
        
        BigInt n = p.mul(q);  // n = pq
        BigInt φ = n.sub(p).sub(q).add(BigInt.ONE);  // φ = n - p - q + 1
        
        // Minimum bitlength for e
        final int MIN = (φ.bitLength() > 20 ? 16 : 0);
        bits = rnd.nextInt(φ.bitLength() - MIN) + MIN;
        
        // MIN < e < φ
        BigInt e = BigInt.probablePrime(bits, rnd);
        BigInt d = inverse(e, φ);
        
        if (debug_numbers){
            System.out.printf("p (%d bits) - %s\n", p.bitLength(), p);
            System.out.printf("q (%d bits) - %s\n", q.bitLength(), q);
            System.out.printf("n (%d bits) - %s\n", n.bitLength(), n);
            System.out.printf("φ (%d bits) - %s\n", φ.bitLength(), φ);
            System.out.printf("d (%d bits) - %s\n", d.bitLength(), d);
            System.out.printf("e (%d bits) - %s\n\n", e.bitLength(), e);
        }
        
        return new BigInt[] {e, d, n};  // {encrypt key, decrypt key, world}
    }
    
    /**
     * Finds the multiplicative inverse of a number in a world if it exists.
     * 
     * @param n         The number to get the inverse of.
     * @param world     The world to get the inverse in.
     * @return          The inverse if it exists, 0 if it does not.
     */
    public static BigInt inverse(BigInt n, BigInt world){
        BigInt[] bezout = extendedEuclid(world, n);  // {GCD, x, y}
        BigInt inverse = BigInt.ZERO;
        
        if (bezout[0].equals(1)){  // if GCD = 1
            inverse = bezout[2];   // inverse = multiples of n
            
            while (inverse.lessThan(0))  // Ensures the inverse is positive
                inverse = inverse.add(world);
        }
        
        return inverse;  // Returns zero if inverse is non existant
    }
    
    /**
     * Calculates how to express the greatest common denominator of two numbers,
     * GCD(a,b), by multiplying a and b each by some integers and adding the
     * results. Uses the extended Euclidean algorithm.
     * 
     * Bézout's identity
     * GCD(a,b) = ax + by for some x,y ϵ Z
     * 
     * @param a         The first number
     * @param b         The second number
     * @return          An array of 3 BigInts - [GCD, x, y]
     */
    public static BigInt[] extendedEuclid(BigInt a, BigInt b){
        BigInt[] x = {a, new BigInt(1), new BigInt(0)};  // Top row
        BigInt[] y = {b, new BigInt(0), new BigInt(1)};  // Bottom row
        
        while (y[0].greaterThan(1)){  // while GCD not found
            BigInt[] temp = {y[0], y[1], y[2]};  // Copy of bottom
            
            BigInt div = x[0].div(y[0]);  // Times to subtract bottom from top
            
            y[0] = x[0].mod(y[0]);
            y[1] = x[1].sub(y[1].mul(div));
            y[2] = x[2].sub(y[2].mul(div));
            
            x = temp;  // Sets top row to old bottom row
        }
        
        return y;
    }
    
    /**
     * Encrypts a message using RSA into a BigInt.
     * Can only encrypt ASCII characters without loss of data.
     * 
     * Splits up the message into segments, each with a bit-length smaller
     * than the world by 1 bit. Each of these is then encrypted. This allows
     * for messages with a bit-length larger than the world to be encrypted.
     * 
     * After each segment is encrypted, they are padded with zeroes at the
     * start to be of an equal length proportional to the world. Finally they
     * are concatenated and turned into a BigInt.
     * 
     * @param m     The message to encrypt
     * @param e     The encrypt key
     * @param n     The world
     * @return      A cipher text string
     */
    public static String encrypt(String m, BigInt e, BigInt n){
        // Max size for each message segment in bytes
        // Value is less than the world byte count by one
        int bytes = (n.bitLength() - 1) / 8;
        
        // Gets the bytes of the message, then splits them into segments of
        // max size 'bytes'. Converts all resulting arrays into BigInts
        BigInt[] bigInts = toNum(m, bytes);
        
        if (debug_encryption)
            debug ("Before encryption", bigInts, toByteArrayArray(bigInts), true);

        // Encrypts each BigInt using the key and world
        for (int i = 0; i < bigInts.length; i++)
            bigInts[i] = powerMod(bigInts[i], e, n);
        
        // Gets byte arrays back from each BigInt
        byte[][] arrays = toByteArrayArray(bigInts);
        
        if (debug_encryption)
            debug("After encryption", bigInts, arrays, false);
        
        // Pads each byte array with zeroes until they have as many bytes as
        // the world plus one
        for (int i = 0; i < arrays.length; i++)
            arrays[i] = pad(arrays[i], (n.bitLength() + 7) / 8 + 1);
        
        if (debug_encryption)
            debug("Padded", bigInts, arrays, false);
        
        // Concats the byte arrays and create a BigInt form them. Returns a
        // string representation of the BigInt
        return new BigInt(concat(arrays)).toString();
    }
    
    /**
     * Decrypts an RSA cipher created by the encrypt() function
     * 
     * @param cipher    The cipher text to decrypt
     * @param d         The decrypt key
     * @param n         The world
     * @return          A string of the decrypted message
     */
    public static String decrypt(String cipher, BigInt d, BigInt n){
        // Creates a BigInt from the cipher and then gets the bytes from it
        byte[] bytes = new BigInt(cipher).toByteArray();
        
        // Splits the bytes into the encrypted message segments
        byte[][] arrays = split(bytes, (n.bitLength() + 7) / 8 + 1, false);
        
        // Converts each segment into a BigInt
        BigInt[] bigInts = toBigIntArray(arrays);
        
        if (debug_encryption)
            debug ("Before decryption", bigInts, arrays, false);
        
        // Decrypts each BigInt using the decrypt key and world
        for (int i = 0; i < bigInts.length; i++)
            bigInts[i] = powerMod(bigInts[i], d, n);
        
        // Converts each BigInt back to a byte array
        arrays = toByteArrayArray(bigInts);
        
        if (debug_encryption)
            debug("After decryption", bigInts, arrays, true);
        
        // Concatenates the byte arrays and recreates the original string
        return new String(concat(arrays));
    }
    
    /**
     * Calculates a number to the power of another in a modular world using
     * fast modular exponentiation.
     * 
     * @param a     The base
     * @param b     The exponent
     * @param c     The world
     * @return      base ^ exponent % world
     */
    public static BigInt powerMod(BigInt a, BigInt b, BigInt c){
        // Binary representation of the power. Allows a^b to be split up into
        // the product of many 'a's, each with an exponent of a power of two.
        String bin = b.toString(2);
        b = BigInt.ONE;
        
        for (int i = bin.length() - 1; i >= 0; i--, a = a.mul(a).mod(c))
            if (bin.charAt(i) == '1')
                b = b.mul(a).mod(c);
        
        return b;
    }
    
    /**
     * Converts a message into an array of numbers.
     * 
     * Splits up the message into sections each with a specified maximum byte
     * count. Each of these segments becomes a number.
     * 
     * @param m             The message to convert
     * @param bytes         The maximum byte count for each segment
     * @return              An array of BigInts encoding the message
     */
    public static BigInt[] toNum(String m, int bytes){
        byte[][] arrays = split(m.getBytes(), bytes);
        
        return toBigIntArray(arrays);
    }
    
    /**
     * Splits a byte array into an array of byte arrays, each with a specified
     * max length.
     * 
     * @param a             The array to split
     * @param bytes         The maximum length for each new array
     * @param left          Whether to start at the left or right
     * @return              An array of byte arrays, containing all values in a
     */
    public static byte[][] split(byte[] a, int bytes, boolean left){
        if (bytes < 1 || a.length == 0)
            return new byte[][]{};
        
        int l = (a.length + bytes - 1) / bytes;
        
        byte[][] split = new byte[l][];
        
        for (int i = 0; i < l - 1; i++)
            split[(left ? i : l - 1 - i)] = new byte[bytes];
        
        split[(left ? l - 1 : 0)] = new byte[(a.length - 1) % bytes + 1];
        
        // Messy code
        for (int i = 0; i < a.length; i ++){
            int x = i / bytes;
            int y = i % bytes;
            
            if (!left){
                x = l - 1 - x;
                
                if (x != 0)
                    y = bytes - 1 - y;
                else
                    y = split[0].length - 1 - y;
            }
            
            split[x][y] = a[(left ? i : a.length - 1 - i)];
        }
        
        return split;
    }
    
    // Default argument version of split()
    public static byte[][] split(byte[] a, int bytes){
        return split(a, bytes, true);
    }
    
    /**
     * Converts an array of byte arrays into an array of BigInts.
     * 
     * @param arrays        The array of byte arrays
     * @return              An array of BigInts created from each byte array
     */
    public static BigInt[] toBigIntArray(byte[][] arrays){
        BigInt[] bigInts = new BigInt[arrays.length];
        
        for (int i = 0; i < arrays.length; i++)
            bigInts[i] = new BigInt(arrays[i]);
        
        return bigInts;
    }
    
    /**
     * Concatenates an array of byte arrays into a single array.
     * 
     * @param a     The array of byte arrays
     * @return      A concatenation of all the byte arrays
     */
    public static byte[] concat(byte[]...a){
        int l = 0;
        
        for (byte[] arr:a)
            l += arr.length;
        
        byte[] ret = new byte[l];
        int i = 0;
        
        for (byte[] arr:a)
            for (byte b:arr){
                ret[i] = b;
                i++;
            }
        
        return ret;
    }
    
    /**
     * Concatenates an array of BigInts into one BigInt. Does so by
     * concatenating the bytes of each BigInt and creating a new BigInt
     * from this.
     * 
     * @param a         The array of BigInts
     * @return          A new BigInt formed from the bytes of others
     */
    public static BigInt concat(BigInt...a){
        byte[][] arrays = new byte[a.length][];
        
        for (int i = 0; i < a.length; i++)
            arrays[i] = a[i].toByteArray();
        
        return new BigInt(concat(arrays));
    }
    
    /**
     * Converts an array of BigInts into an array of byte arrays. Takes the
     * bytes in each BigInt and stores them all in an array.
     * 
     * @param bigInts       The array of BigInts.
     * @return              An array of each BigInts bytes
     */
    public static byte[][] toByteArrayArray(BigInt[] bigInts){
        byte[][] arrays = new byte[bigInts.length][];
        
        for (int i = 0; i < arrays.length; i++)
            arrays[i] = bigInts[i].toByteArray();
        
        return arrays;
    }
    
    /**
     * Pads a byte array with zeroes at the start to make it a specified length.
     * 
     * @param bytes         The array of bytes
     * @param length        The length to pad to
     * @return              A padded version of the inputted byte array
     */
    public static byte[] pad(byte[] bytes, int length){
        if (length <= bytes.length)
            return bytes;
        
        byte[] ret = new byte[length];
        
        int dif = length - bytes.length;
        
        for (int i = 0; i < bytes.length; i++)
            ret[i + dif] = bytes[i];
        
        return ret;
    }
    
    
    
    
    
    
    
    
    
    
    // Debug functions
    public static void debug(String header, BigInt[] a, byte[][] b, boolean asString){
        header(header);
        
        for (int i = 0; i < a.length; i++){
            String s = new String(a[i].toByteArray());
            
            System.out.printf("Segment %d (%d bits): %s\nBytes: ", i, a[i].bitLength(), (asString ? "'" +  s + "'" : ""));
            print(a[i].toByteArray());
            System.out.printf("BigInt: %s\n\n", a[i]);
        }
    }
    
    public static void header(String m){
        char horizontal = '-';
        
        for (int i = 0; i < m.length(); i++)
            System.out.print(horizontal);
        
        System.out.printf("\n%s\n", m);
        
        for (int i = 0; i < m.length(); i++)
            System.out.print(horizontal);
        
        System.out.print("\n");
    }
    
    /**
     * Prints the values stored in a byte array.
     * 
     * @param a     The byte array to print
     */
    public static void print(byte[] a){
        System.out.print("[");
        
        for (int i = 0; i < a.length - 1; i++){
            int x = a[i] + 0;
            
            String s = Integer.toHexString(Math.abs(x));
            s = s.toUpperCase();
            
            if (s.length() == 1)
                s = "0" + s;
            
            System.out.printf("%s, ", s);
        }
        
        if (a.length > 0){
            int x = a[a.length - 1] + 0;
            
            String s = Integer.toHexString(Math.abs(x));
            s = s.toUpperCase();
            
            if (s.length() == 1)
                s = "0" + s;
            
            System.out.print(s);
        }
        
        System.out.print("]\n");
    }
}
