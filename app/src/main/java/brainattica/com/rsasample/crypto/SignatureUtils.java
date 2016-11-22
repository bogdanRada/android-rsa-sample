package brainattica.com.rsasample.crypto;


import android.os.Build;
import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.Signature;
import java.security.SignatureException;




/**
 * http://www.xinotes.net/notes/note/1900/
 * Created by javiermanzanomorilla on 11/02/15.
 */
public class SignatureUtils {


    private static Signature getSignature() throws RuntimeException {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return  Signature.getInstance("SHA256withRSA");
            } else{
                return   Signature.getInstance("SHA256withRSA", "AndroidOpenSSL");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Signature getInstance() {
            Signature s = getSignature();
          //  Signature s = Signature.getInstance("SHA256withRSA/PSS", new BouncyCastleProvider());
//            PSSParameterSpec spec1 = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 0, 1);
//            s.setParameter(spec1);
            return s;
    }

    public static String genSignature(String text) {
        try {
            Signature s = getInstance();
            KeyStore.PrivateKeyEntry entry = RSA.getPrivateKeyEntry();
            s.initSign(entry.getPrivateKey());
            s.update(text.getBytes());
            return RSA.stringify(Base64.encode(s.sign(), Base64.DEFAULT));
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean checkSignature(String signature, String input) {
        try {
            Signature s = getInstance();
            KeyStore.PrivateKeyEntry entry = RSA.getPrivateKeyEntry();
            s.initVerify(entry.getCertificate().getPublicKey());
            s.update(input.getBytes());
            return s.verify(Base64.decode(signature.getBytes(), Base64.DEFAULT));
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

