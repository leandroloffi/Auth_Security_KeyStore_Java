package aplication_auth;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.security.cert.Certificate;

/**
 * Código para demonstrar o uso do keystore padrão FIPS da BouncyCastle Esse
 * keystore guarda chaves secretas (simétricas), certificados de chaves públicas e chaves privadas
 *
 * @author Carla
 * @version 2.0 - agosto de 2017
 */
public class Keystore {

    public static void storeSecretKey(String storeFilename, char[] storePassword, String alias, char[] keyPass, SecretKey secretKey)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(new FileInputStream(storeFilename), storePassword);
        //keyStore.load(null, null);

        keyStore.setKeyEntry(alias, secretKey, keyPass, null);
        keyStore.store(new FileOutputStream(storeFilename), storePassword);
    }

    public static void storeCertificate(String storeFilename, char[] storePassword, String alias, X509Certificate trustedCert)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(new FileInputStream(storeFilename), storePassword);
        keyStore.setCertificateEntry(alias, trustedCert);
        keyStore.store(new FileOutputStream(storeFilename), storePassword);

    }

    public static void storePrivateKey(String storeFilename, char[] storePassword, String alias, char[] keyPass, PrivateKey eeKey, X509Certificate[] eeCertChain)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(new FileInputStream(storeFilename), storePassword);
        keyStore.setKeyEntry(alias, eeKey, keyPass, eeCertChain);
        keyStore.store(new FileOutputStream(storeFilename), storePassword);
    }

    static void printKeyStore(String storeFilename, char[] storePassword) throws NoSuchProviderException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");
        keyStore.load(new FileInputStream(storeFilename), storePassword);
        System.out.println("KeyStore type: " + keyStore.getType());
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String elem = aliases.nextElement();
            if (keyStore.isKeyEntry(elem)) 
                System.out.println("Chave = "+ elem);
            else
                if (keyStore.isCertificateEntry(elem)) {
                    System.out.println("Certificado = "+elem);
                    Certificate cert = keyStore.getCertificate(elem);
                    System.out.println("Chave publica guardada no certificado:"+cert.getPublicKey());
                    System.out.println("Tipo do certificado:"+cert.getType());
                }
        }

    }

}
