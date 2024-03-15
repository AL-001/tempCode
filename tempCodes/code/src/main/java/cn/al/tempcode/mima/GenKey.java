package cn.al.tempcode.mima;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class GenKey {
    public static void main(String[] args) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec sm2p256v1 = new ECGenParameterSpec("sm2p256v1");
        KeyPairGenerator ecg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom secureRandom = new SecureRandom();
        ecg.initialize(sm2p256v1,secureRandom);
        KeyPair keyPair = ecg.generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        System.out.println("sm2 public key:\n"+ Base64.toBase64String(aPublic.getEncoded()));
        System.out.println("sm2 private key:\n"+ Base64.toBase64String(aPrivate.getEncoded()));
    }
}
