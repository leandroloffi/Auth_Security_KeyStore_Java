/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aplication_auth;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class Utils {
    
    private static String nomeKS = "keystore.txt";
    
    private static String	digits = "0123456789abcdef";

    
    /**
     * Return length many bytes of the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;
            
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
    
    /**
     * Return the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    /**
     * Create a key for use with AES.
     * 
     * @param bitLength
     * @param random
     * @return an AES key.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(
        int          bitLength,
        SecureRandom random)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        
        generator.init(128, random);
        
        return generator.generateKey();
    }
    
    /**
     * Create an IV suitable for using with AES in CTR mode.
     * <p>
     * The IV will be composed of 4 bytes of message number,
     * 4 bytes of random data, and a counter of 8 bytes.
     * 
     * @param messageNumber the number of the message.
     * @param random a source of randomness
     * @return an initialised IvParameterSpec
     */
    public static IvParameterSpec createCtrIvForAES(
        int             messageNumber,
        SecureRandom    random)
    {
        byte[]          ivBytes = new byte[16];
        
        // initially randomize
        
        random.nextBytes(ivBytes);
        
        // set the message number bytes
        
        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);
        
        // set the counter bytes to 1
        
        for (int i = 0; i != 7; i++)
        {
            ivBytes[8 + i] = 0;
        }
        
        ivBytes[15] = 1;
        
        return new IvParameterSpec(ivBytes);
    }
    
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(
        byte[] bytes,
        int    length)
    {
        char[]	chars = new char[length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }
    
    public static byte[] toByteArray(String string){
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++){
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }
    
    public boolean verificacao(KeyStore ks, String aliasKS11, String aliasKS12, String aliasKS21, String aliasKS22) throws KeyStoreException{
        if(ks.containsAlias(aliasKS11) && ks.containsAlias(aliasKS12) 
            && ks.containsAlias(aliasKS21) && ks.containsAlias(aliasKS22)){
            return true;
        }
        return false;
    }
    
    public String chaveDerivada64(String senha, String salt, int it){
        return generateDerivedKey(senha, salt, it, 64);
    }
    public String chaveDerivada128(String senha, String salt, int it){
        return generateDerivedKey(senha, salt, it, 128);
    }
    public String chaveDerivada128vA(String chave){
        String chaveA = "";
        char[] text = chave.toCharArray();
        for (int i = 0; i < text.length; i++) {
            if(i < 32){
                chaveA += text[i];
            }
        }
        return chaveA;
    }
    public String chaveDerivada128vD(String chave){
        String chaveD = "";
        for (int i = 0; i < chave.length(); i++) {
            if(i >= 32 && i < 64){
                chaveD += chave.charAt(i);
            }
        }
        return chaveD;
    }
    
    public String chaveDerivada256(String senha, String salt, int it){
        return generateDerivedKey(senha, salt, it, 256); 
    }
    
    Boolean verificacaoNKS(String chaveDerivada) throws IOException{ 
        
        ArrayList<String> al = lerConteudoArquivo(nomeKS);
        
        if(al.size()>0){
            for (int i = 0; i < al.size(); i++) {
                if(al.get(i).equalsIgnoreCase(chaveDerivada+";")){
                    return true;
                }
            }
        }
        
        //gravaArquivoIntern(nomeKS, chaveDerivada);
        return false;
    }
    
    Boolean verificacaoUKS(String nomeDir, String valor) throws IOException{ 
        
        ArrayList<String> al = lerConteudoArquivo(nomeDir);
        
        if(al.size()>0){
            for (int i = 0; i < al.size(); i++) {
                if(al.get(i).equalsIgnoreCase(valor+";")){
                    return true;
                }
            }
        }
        
        //gravaArquivoIntern(nomeKS, chaveDerivada);
        return false;
    }
    
    //Para ler o arquivo para uma String
    public ArrayList<String> lerConteudoArquivo(String arq) throws IOException {
        ArrayList<String> al = new ArrayList<String>();
        File arquivo = new File(arq);
        if(new FileReader(arquivo) == null){
            System.out.println("NULLO");
        }else{
            System.out.println("NÃO NULLO");
        }
        
        BufferedReader conteudo = new BufferedReader(new FileReader(arquivo));
        while (conteudo.ready()) {
             al.add(conteudo.readLine()); // lê da segunda até a última linha
        }
        return al;
    }

    //Para gravar em um arquivo
    public void gravaArquivo( String conteudo) {
        File arquivo = new File(nomeKS);
        try {
            FileWriter grava = new FileWriter(arquivo, true);
            PrintWriter escreve = new PrintWriter(grava);
            escreve.println(conteudo+";");
            escreve.close();
            grava.close();
        } catch (IOException ex) {
           System.err.printf("Erro na abertura do arquivo: %s.\n",ex.getMessage());
        }
    }
    
    public void gravaArquivoIntern(String nomeArquivo, String conteudo) {
        File arquivo = new File(nomeArquivo);
        try {
            FileWriter grava = new FileWriter(arquivo, true);
            PrintWriter escreve = new PrintWriter(grava);
            escreve.println(conteudo+";");
            escreve.close();
            grava.close();
        } catch (IOException ex) {
           System.err.printf("Erro na abertura do arquivo: %s.\n",ex.getMessage());
        }
    }
    
    public byte[] cifragemGCM(byte[] k, byte[] input, byte[] iv) throws Exception {

        Cipher in = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");

        Key key = new SecretKeySpec(k, "AES");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        return in.doFinal(input);

    }
    
    public String decifragemGCM(byte[] k, byte[] cipher, byte[] iv) throws Exception{
        
        Key key = new SecretKeySpec(k, "AES");
        Cipher out = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        
        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return Utils.toString(out.doFinal(cipher));
    }
    
    public byte [] cifragemHMAC(Cipher cipher, String input, Key key, IvParameterSpec ivSpec, Mac hMac, Key hMacKey) throws Exception {
        // Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        
        // etapa de cifragem
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hMac.getMacLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(input));
        
        byte[] hmacfinal = hMac.doFinal();
        
        ctLength += cipher.doFinal(hmacfinal, 0, hMac.getMacLength(), cipherText, ctLength);
        
        return cipherText;
    }
    
    public String decifragemHMAC(Cipher cipher, byte[] cipherText, Key key, IvParameterSpec ivSpec, Mac hMac, Key hMacKey) throws Exception {
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] plainText = cipher.doFinal(cipherText, 0, cipherText.length);
        int    messageLength = plainText.length - hMac.getMacLength();
        
        hMac.init(hMacKey);
        hMac.update(plainText, 0, messageLength);
        
        byte[] messageMac = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageMac, 0, messageMac.length);
        
        byte[] te = hMac.doFinal();
        
        if(!MessageDigest.isEqual(te, messageMac)){
            return "";
        }
        
        return Utils.toString(plainText, messageLength);
    }
    
    public String generateDerivedKey(
            String password, String salt, Integer iterations, int tamanho) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, tamanho);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return derivedPass;
    }
    
    /*Usado para gerar o salt  */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }
    
}
