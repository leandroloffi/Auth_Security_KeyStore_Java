/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aplication_auth;

import java.util.Scanner;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class Aplication_Auth {

    public static void main(String[] args)
            throws GeneralSecurityException, IOException, OperatorCreationException, Exception, UnrecoverableKeyException {

        String senhaKeyStore = "";
        String nomeKeyStore = "";
        int nIT = 0;
        String senhaSys = "";
        String nomeSys = "";

        Utils util = new Utils();
        Scanner ler = new Scanner(System.in);
        // Install Provider FIPS
        Security.addProvider(new BouncyCastleFipsProvider());

        // Adicionado para resolver problema da lentidao no Linux - Sugerido por Marcio Sagaz
        CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC
                .fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));

        String EntKeyStore = "";

        do {

            System.out.print("\nBEM-VINDO AO AUTHENTICATE\n\nAutenticação KeyStore\nO que você deseja fazer? \n"
                    + "( 1 - Criar novo KeyStore | 2 - Autenticar em algum KeyStore "
                    + "| 3 - Sair): ");
            EntKeyStore = ler.next();
            String chaveKeystore = "";
            String nomeDIR = "";
            KeyStore ks = null;
            if (EntKeyStore.equalsIgnoreCase("2") || EntKeyStore.equalsIgnoreCase("1")) {
                boolean sair;
                do {
                    sair = false;
                    // ENTRADAS KEYSTORE
                    System.out.println("ENTRADA NO KEYSTORE");
                    System.out.print("NOME Key Store: ");
                    nomeKeyStore = ler.next();
                    System.out.print("SENHA Key Store: ");
                    senhaKeyStore = ler.next();
                    System.out.print("SEU NÚMERO (IT): ");
                    nIT = ler.nextInt();
                    if (nomeKeyStore.equals(senhaKeyStore)) {
                        System.out.println("O nome tem que ser diferente da Senha!");
                    }
                    // Criar o keystore no diretorio atual
                    ks = KeyStore.getInstance("BCFKS", "BCFIPS");

                    chaveKeystore = util.chaveDerivada128(nomeKeyStore, senhaKeyStore, nIT);
                    nomeDIR = util.chaveDerivada128(chaveKeystore, nomeKeyStore, nIT);

                    if (EntKeyStore.equalsIgnoreCase("1")) {
                        System.out.println("CRIANDO NOVO KEY STORE");
                        // Cria do zero o keystore
                        ks.load(null, null);
                        ks.store(new FileOutputStream(nomeDIR + ".bcfks"), chaveKeystore.toCharArray());
                        if (!util.verificacaoNKS(chaveKeystore)) {
                            util.gravaArquivo(chaveKeystore);
                        }
                    } else if (EntKeyStore.equalsIgnoreCase("2")) {
                        if (util.verificacaoNKS(chaveKeystore)) {
                            System.out.println("ACESSANDO KEY STORE COM NOME: " + nomeKeyStore + ", SENHA: " + senhaKeyStore + ", IT: " + nIT);
                            ks.load(new FileInputStream(nomeDIR + ".bcfks"), chaveKeystore.toCharArray());
                        } else {
                            System.out.println("DADOS INVÁLIDOS\n");
                            sair = true;
                        }
                    }
                    // FIM ENTRADA
                } while (nomeKeyStore.equals(senhaKeyStore) || sair == true);

                boolean parar;
                String EntUsuario = "";
                boolean encontro;
                do {
                    parar = true;
                    encontro = false;

                    System.out.print("\nAutenticação Usuário\nO que você deseja fazer? \n"
                            + "( 1 - Criar novo Usuário | 2 - Autenticar com algum usuário "
                            + "| 3 - Sair): ");
                    EntUsuario = ler.next();

                    if (EntUsuario.equalsIgnoreCase("1") || EntUsuario.equalsIgnoreCase("2")) {
                        do {
                            // ENTRADAS USUARIO E SENHA SISTEMA
                            System.out.print("USUÁRIO: ");
                            nomeSys = ler.next();
                            System.out.print("SENHA: ");
                            senhaSys = ler.next();
                            if (nomeSys.equals(senhaSys)) {
                                System.err.println("O nome tem que ser diferente da Senha!");
                            }
                            // FIM ENTRADA
                        } while (nomeSys.equals(senhaSys));

                        //DERIVANDO CHAVE DO SISTEMA COM PBKDF 
                        String KS11 = util.chaveDerivada256(senhaSys, nomeSys, nIT);
                        String KS12 = util.chaveDerivada256(senhaKeyStore, KS11, nIT);

                        // String KS11 = util.chaveDerivada256(senhaSys, chaveKeystore, nIT);
                        //String KS12 = util.chaveDerivada256(nomeSys, chaveKeystore, nIT);
                        String aliasKS11 = util.chaveDerivada128vA(KS11);
                        String aliasKS12 = util.chaveDerivada128vA(KS12);
                        String passwordKS11 = util.chaveDerivada128vD(KS11);
                        String passwordKS12 = util.chaveDerivada128vD(KS12);
                        String IVKS = util.chaveDerivada256(nomeSys, chaveKeystore, nIT);
                        String chaveKS = util.chaveDerivada256(senhaSys, nomeSys, nIT);

                        String KS21 = util.chaveDerivada256(senhaSys, KS11, nIT);
                        String KS22 = util.chaveDerivada256(nomeSys, KS12, nIT);

                        String aliasKS21 = util.chaveDerivada128vA(KS21);
                        String aliasKS22 = util.chaveDerivada128vA(KS22);
                        String passwordKS21 = util.chaveDerivada128vD(KS21);
                        String passwordKS22 = util.chaveDerivada128vD(KS22);
                        String IVKS2 = util.chaveDerivada256(nomeSys, IVKS, nIT);
                        String chaveKS2 = util.chaveDerivada256(senhaSys, chaveKS, nIT);

                        if (EntUsuario.equalsIgnoreCase("1")) {

                            if (!util.verificacao(ks, aliasKS11, aliasKS12, aliasKS21, aliasKS22)) {

                                byte[] bytes2 = new BigInteger("7F" + IVKS, 16).toByteArray();
                                SecretKeySpec IVKSK = new SecretKeySpec(bytes2, 1, bytes2.length - 1, "AES");

                                byte[] bytes3 = new BigInteger("7F" + chaveKS, 16).toByteArray();
                                SecretKeySpec chaveKSK = new SecretKeySpec(bytes3, 1, bytes3.length - 1, "AES");

                                //SEGUNDA DERIVAÇÃO
                                byte[] bytes4 = new BigInteger("7F" + IVKS2, 16).toByteArray();
                                SecretKeySpec IVKSK2 = new SecretKeySpec(bytes4, 1, bytes4.length - 1, "AES");

                                byte[] bytes5 = new BigInteger("7F" + chaveKS2, 16).toByteArray();
                                SecretKeySpec chaveKSK2 = new SecretKeySpec(bytes5, 1, bytes5.length - 1, "AES");

                                // Armazena duas chaves secretass
                                ks.load(new FileInputStream(nomeDIR + ".bcfks"), chaveKeystore.toCharArray());
                                ks.setKeyEntry(aliasKS11, IVKSK, (passwordKS11).toCharArray(), null);
                                ks.setKeyEntry(aliasKS12, chaveKSK, (passwordKS12).toCharArray(), null);
                                ks.setKeyEntry(aliasKS21, IVKSK2, (passwordKS21).toCharArray(), null);
                                ks.setKeyEntry(aliasKS22, chaveKSK2, (passwordKS22).toCharArray(), null);
                                ks.store(new FileOutputStream(nomeDIR + ".bcfks"), chaveKeystore.toCharArray());

                            } else {
                                System.err.println(">> Encontrado um Usuário Igual cadastrado no KeyStore!");
                                encontro = true;
                            }
                        }

                        // Recupera chaves do keystore e imprime as chaves na tela 
                        SecretKey sk1 = (SecretKey) ks.getKey(aliasKS11, (passwordKS11).toCharArray());
                        SecretKey sk2 = (SecretKey) ks.getKey(aliasKS12, (passwordKS12).toCharArray());
                        SecretKey sk3 = (SecretKey) ks.getKey(aliasKS21, (passwordKS21).toCharArray());
                        SecretKey sk4 = (SecretKey) ks.getKey(aliasKS22, (passwordKS22).toCharArray());

                        if (sk1 != null && sk2 != null && sk3 != null && sk4 != null) {

                            // PRIMEIROS 16 BYTES DA CHAVE DO IV
                            byte[] iv = new byte[16];
                            for (int i = 0; i < 16; i++) {
                                iv[i] = sk1.getEncoded()[i];
                            }

                            // HMAC
                            IvParameterSpec ivSpec = new IvParameterSpec(iv);
                            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
                            Mac hMac = Mac.getInstance("HMacSHA256", "BCFIPS");
                            Key hMacKey = new SecretKeySpec(sk2.getEncoded(), "HMacSHA256");

                            byte[] cipherText = util.cifragemHMAC(cipher, nomeSys, sk2, ivSpec, hMac, hMacKey);
                            System.out.println("Cifragem HMAC>> " + Hex.encodeHexString(cipherText));
                            String decHmac = util.decifragemHMAC(cipher, cipherText, hMacKey, ivSpec, hMac, hMacKey);
                            System.out.println("Decifragem>> " + decHmac);
                            // FIM HMAC

                            // PRIMEIROS 16 BYTES DA CHAVE DO IV
                            byte[] iv2 = new byte[16];
                            for (int i = 0; i < 16; i++) {
                                iv2[i] = sk3.getEncoded()[i];
                            }

                            // GCM
                            byte[] cif = util.cifragemGCM(sk4.getEncoded(), senhaSys.getBytes(), iv2);
                            System.out.println("Cifragem GCM>> " + Hex.encodeHexString(cif));
                            String decGCM = util.decifragemGCM(sk4.getEncoded(), cif, iv2);
                            System.out.println("Decifragem>> " + decGCM);
                            // FIM GCM
                            if (encontro != true) {
                                util.gravaArquivoIntern(nomeDIR + ".txt", Hex.encodeHexString(cipherText));
                                util.gravaArquivoIntern(nomeDIR + ".txt", Hex.encodeHexString(cif));
                            }

                            if (EntUsuario.equalsIgnoreCase("1")) {
                                System.out.println("Criação de usuário Completa!");
                            }

                            if (EntUsuario.equalsIgnoreCase("2")) {
                                System.out.println(">> " + senhaSys);
                                System.out.println(">> " + decGCM);
                                if (decGCM.equals(senhaSys) && decHmac.equals(nomeSys)) {
                                    System.out.println("\n\n--USUÁRIO AUTENTICADO--\n");
                                } else {
                                    System.err.println("Erro na Autenticação.\n");
                                }
                            }
                        } else {
                            System.err.println("Erro na Autenticação.\n");
                        }

                    }
                } while (!EntUsuario.equalsIgnoreCase("3"));
            }

        } while (!"3".equalsIgnoreCase(EntKeyStore));

    }
}
