package brainattica.com.rsasample.crypto;

import android.content.Context;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import brainattica.com.rsasample.utils.Preferences;


/**
 * Created by javiermanzanomorilla on 24/12/14.
 */
public class RSA {

//    static {
//        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
//    }

    private static final String TAG = RSA.class.getSimpleName();

    public  static KeyStore keyStore;

    public static PublicKey publicKey;
    public static PrivateKey privateKey;

    private static final int KEY_SIZE = 1024;


    public static KeyStore loadKeyStore() throws RuntimeException{
        try{
            RSA.keyStore = KeyStore.getInstance("AndroidKeyStore");
            RSA.keyStore.load(null);
            return RSA.keyStore;
        }catch(Exception e){

            throw new RuntimeException(e);
        }
    }


    private static Cipher getCipher() throws RuntimeException {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return  Cipher.getInstance("RSA/ECB/PKCS1Padding");
            } else{
                return  Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static KeyPair generate(Context context) {
        try {
            loadKeyStore();
            SecureRandom random = new SecureRandom();
            String uid = UUID.randomUUID().toString().replaceAll("-", "");
            Preferences.putString(Preferences.RSA_ALIAS, uid);
//            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4);
//            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SC");
//            generator.initialize(spec, random);
//            return generator.generateKeyPair();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");


            Calendar start = new GregorianCalendar();
            Calendar end = new GregorianCalendar();
            end.add(Calendar.YEAR, 1);

            android.security.KeyPairGeneratorSpec spec = new  android.security.KeyPairGeneratorSpec.Builder(context)
                    // You'll use the alias later to retrieve the key. It's a key
                    // for the key!
                    .setAlias(uid)
                    .setSubject(new X500Principal("CN=" + uid))
                    .setSerialNumber(BigInteger.valueOf(Math.abs(uid.hashCode())))
                    // Date range of validity for the generated pair.
                    .setStartDate(start.getTime()).setEndDate(end.getTime())
                    .build();

            generator.initialize(spec, random);

            KeyPair kp = generator.generateKeyPair();
            PublicKey publicKey = kp.getPublic();

            attachCertificateToAlias(uid, publicKey.getEncoded());

            return kp;
        } catch (Exception e) {
            Log.wtf("aha", e);
            throw new RuntimeException(e);
        }
    }


    private static Certificate attachCertificateToAlias(String alias, byte[] publicKey) throws RuntimeException{
        try {

            KeyStore.PrivateKeyEntry existingPrivateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);

            if (existingPrivateKeyEntry.getCertificate() == null ) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(publicKey));
                PrivateKey privateKey = existingPrivateKeyEntry.getPrivateKey();

                KeyStore.PrivateKeyEntry newEntry = new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{cert});
                keyStore.setEntry(alias, newEntry, null);
                keyStore.setCertificateEntry(alias, cert);
                return cert;
            }
            else {
                return existingPrivateKeyEntry.getCertificate();
            }
        }catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] toBeCiphred) {
        try {
        //    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "SC");
            Cipher rsaCipher = RSA.getCipher();
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return rsaCipher.doFinal(toBeCiphred);
        } catch (Exception e) {
            Log.e(TAG, "Error while encrypting data: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static String encryptToBase64(PublicKey publicKey, String toBeCiphred) {
        try {
            byte[] cyphredText = RSA.encrypt(publicKey, toBeCiphred.getBytes("UTF-8"));
            return Base64.encodeToString(cyphredText, Base64.DEFAULT);
        }catch(Exception e){
            Log.wtf("encryptToBase64", e);
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedText) {
        try {
          //  Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "SC");
            Cipher rsaCipher = RSA.getCipher();
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return rsaCipher.doFinal(encryptedText);
        } catch (Exception e) {
            Log.e(TAG, "Error while decrypting data: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static String decryptFromBase64(PrivateKey key, String cyphredText) {
        byte[] afterDecrypting = RSA.decrypt(key, Base64.decode(cyphredText, Base64.DEFAULT));
        return stringify(afterDecrypting);
    }

    public static String encryptWithKey(String key, String text) {
        try {
            KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry();
            if (entry != null) {
                PublicKey apiPublicKey = entry.getCertificate().getPublicKey();
                return encryptToBase64(apiPublicKey, text);
            }
           else{
                return null;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static  KeyStore.PrivateKeyEntry  getPrivateKeyEntry(){
        try {
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) RSA.loadKeyStore().getEntry(Preferences.getString(Preferences.RSA_ALIAS), null);
            return entry;
        }catch(Exception e){
            Log.wtf("getkeys", e);
            return null;
        }
    }

    public static String encryptWithStoredKey(String text) {
        return encryptWithKey(null, text);
    }

    public static String decryptWithStoredKey(String text) {
        try {
            KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry();
            if (entry != null) {
                PrivateKey privateKey = entry.getPrivateKey();
                return decryptFromBase64(privateKey, text);
            }else{
                return null;
            }
        } catch (Exception e) {
            Log.e("a", "a", e);
            return null;
        }
    }

    private static class FixedRand extends SecureRandom {

        MessageDigest sha;
        byte[] state;

        FixedRand() {
            try {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("can't find SHA-1!");
            }
        }

        public void nextBytes(byte[] bytes) {

            int off = 0;

            sha.update(state);

            while (off < bytes.length) {
                state = sha.digest();

                if (bytes.length - off > state.length) {
                    System.arraycopy(state, 0, bytes, off, state.length);
                } else {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }

                off += state.length;

                sha.update(state);
            }
        }
    }


    public static String stringify(byte[] bytes) {
        return stringify(new String(bytes));
    }

    private static String stringify(String str) {
        String aux = "";
        for (int i = 0; i < str.length(); i++) {
            aux += str.charAt(i);
        }
        return aux;
    }


}
