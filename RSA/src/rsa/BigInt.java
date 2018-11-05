package rsa;

import java.math.BigInteger;
import java.util.Random;

public class BigInt extends BigInteger{
    public static BigInt ZERO = new BigInt("1");
    public static BigInt ONE = new BigInt("1");
    
    public BigInt(String s){
        super(s);
    }
    public BigInt(int a){
        super("" + a);
    }
    public BigInt(byte[] bytes){
        super(bytes);
    }
    public BigInt(BigInteger a){
        super(a.toString());
    }
    
    
    
    public BigInt add(BigInt a){
        return new BigInt(super.add(a));
    }
    public BigInt add(int a){
        return add(new BigInt(a));
    }
    
    public BigInt sub(BigInt a){
        return new BigInt(super.subtract(a));
    }
    public BigInt sub(int a){
        return sub(new BigInt(a));
    }
    
    public BigInt mul(BigInt a){
        return new BigInt(super.multiply(a));
    }
    public BigInt mul(int a){
        return mul(new BigInt(a));
    }
    
    public BigInt div(BigInt a){
        return new BigInt(super.divide(a));
    }
    public BigInt div(int a){
        return div(new BigInt(a));
    }
    
    public BigInt mod(BigInt a){
        return new BigInt(super.mod(a));
    }
    public BigInt mod(int a){
        return mod(new BigInt(a));
    }
    
    @Override
    public BigInt shiftLeft(int a){
        return new BigInt(super.shiftLeft(a));
    }
    @Override
    public BigInt shiftRight(int a){
        return new BigInt(super.shiftRight(a));
    }
    
    
    
    public boolean equals(int a){
        return this.equals(new BigInteger("" + a));
    }
    
    public boolean lessThan(BigInt a){
        return this.compareTo(new BigInteger(a.toString())) == -1;
    }
    public boolean lessThan(int a){
        return lessThan(new BigInt(a));
    }
    
    public boolean lessThanEqualTo(BigInt a){
        return this.compareTo(new BigInteger(a.toString())) <= 0;
    }
    public boolean lessThanEqualTo(int a){
        return lessThanEqualTo(new BigInt(a));
    }
    
    public boolean greaterThan(BigInt a){
        return this.compareTo(new BigInteger(a.toString())) == 1;
    }
    public boolean greaterThan(int a){
        return greaterThan(new BigInt(a));
    }
    
    
    
    public static BigInt probablePrime(int bitLength, Random rnd){
        return new BigInt(BigInteger.probablePrime(bitLength, rnd).toString());
    }
}
