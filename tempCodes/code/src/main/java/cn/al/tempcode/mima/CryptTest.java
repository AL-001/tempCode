package cn.al.tempcode.mima;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptTest {
    //客户端私钥钥 x509格式
    public static final String clientPri = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgOkWl7SBTpVPxkstv/ThumCX5KfM4F7dN4DT4ZFZXwDigCgYIKoEcz1UBgi2hRANCAAS3krZThwHIJo0vfW1kdmOY1gdNZy9n2WJSDIgq87RopOq4a8m70+QtyDFjYsi6Lw8YeSxZqZzeHmuTvveV/iiL";
    //客户端公钥 pkcs8格式
    public static final String clinePub = "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBA0IABLeStlOHAcgmjS99bWR2Y5jWB01nL2fZYlIMiCrztGik6rhrybvT5C3IMWNiyLovDxh5LFmpnN4ea5O+95X+KIs=";
    //服务端私钥
    public static final String serverPub = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAENLxzZ1nEP9CC8K+kE3mmZYTHZt57OmVxJ7buwhWDMP5LaBrJ+X7V08v87qEGsKZF1OtOuMSn8g/iH3EnrBRx5w==";

    public static  final X9ECParameters namedCurves = GMNamedCurves.getByName("sm2p256v1");

    public static final ECDomainParameters sm2Paras  = new ECDomainParameters(namedCurves.getCurve(),namedCurves.getG(),namedCurves.getN(),namedCurves.getH());
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args)throws Exception  {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decode(clientPri));
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decode(clinePub));
        KeyFactory ecKeyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey privateKey = ecKeyFactory.generatePrivate(pkcs8EncodedKeySpec);
        PublicKey publicKey = ecKeyFactory.generatePublic(x509EncodedKeySpec);
        String source = "123456saasdasdasdasdasdasdasdasdasdasfdgsd阿三大苏打实打实的1123456saasdasdasdasdasdasdasdasdasdasfdgsd阿三大苏打实打实的1123456saasdasdasdasdasdasdasdasdasdasfdgsd阿三大苏打实打实的1";

        //sm2加密解密
        byte[] bytes = source.getBytes(StandardCharsets.UTF_8);
        byte[] sm2Encrypt = sm2Encrypt(bytes,publicKey);
        byte[] sm2Decrypt = sm2Decrypt(sm2Encrypt,privateKey);
        System.out.println("原文: "+ source +",sm2 加密解密后: "+ new String(sm2Decrypt,StandardCharsets.UTF_8));

        //sm4加密解密
        byte[] sm4Key = genSm4Key();
        byte[] encrypt = sm4Encrypt(sm4Key, bytes);
        byte[] decrypt = sm4Decrypt(sm4Key, encrypt);
        System.out.println("原文: \n"+ source +"\nsm4 加密解密后: \n"+ new String(decrypt,StandardCharsets.UTF_8));

        //签名验签
        byte[] sign1 = sm3WithSm2Sign(bytes,privateKey);
        byte[] sign2 = sm3WithSm2Sign(bytes,privateKey);
        System.out.println("clientPri 签名1: " + Hex.toHexString(sign1) + "\nclientPri 签名2: "+ Hex.toHexString(sign2));
        boolean b1 = sm3WithSm2Verify(bytes, sign1,publicKey);
        boolean b2 = sm3WithSm2Verify(bytes, sign2,publicKey);
        System.out.println("clinePub 验证 clientPri的签名1:: " + b1 + "clinePub 验证 clientPri的签名2: "+ b2);

        //用其他私钥签名
        KeyPair keyPair = sm2KeyPair();
        PrivateKey fakeKey = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
        byte[] sign = sm3WithSm2Sign(bytes, fakeKey);
        System.out.println("fakeKey签名: " + Hex.toHexString(sign));
        boolean b3 = sm3WithSm2Verify(bytes, sign,publicKey);
        System.out.println("clinePub 验证 fakeKey的签名: " + b3);

    }

    /**
     * sm2 c1c3c2  c1首字节为0x04
     * @param sourceByte 原文
     * @return 加密后bytes
     */
    public static byte[]  sm2Encrypt(byte[] sourceByte,PublicKey publicKey) throws Exception {
        SM2Engine sm2Engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(ECUtil.generatePublicKeyParameter(publicKey),new SecureRandom()));
        return sm2Engine.processBlock(sourceByte,0,sourceByte.length);
    }
    /**
     * 对原字符串 utf-8编码后，sm2 c1c3c2 c1首字节为0x04
     * @param encryptedBytes sm2加密后的bytes数组
     * @return 加密后数据，base64编码
     */
    public static byte[]  sm2Decrypt(byte[] encryptedBytes,PrivateKey privateKey) throws Exception {
        SM2Engine sm2Engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        sm2Engine.init(false, ECUtil.generatePrivateKeyParameter(privateKey));
        return sm2Engine.processBlock(encryptedBytes,0,encryptedBytes.length);
    }

    /**
     * sm3withsm2 签名， 默认id 1234567812345678
     * @param source
     * @return rs拼接签名 ,非标准操作， 不是原始的r , s
     * @throws Exception
     */
    public static byte[] sm3WithSm2Sign(byte[] source,PrivateKey privateKey) throws Exception {
        Signature sm3WithSM2 = Signature.getInstance("SM3WithSM2",BouncyCastleProvider.PROVIDER_NAME);
//        SM2Signer sm2Signer = new SM2Signer();
//        sm2Signer.generateSignature();
        sm3WithSM2.initSign(privateKey);
        sm3WithSM2.update(source);
        byte[] sign = sm3WithSM2.sign();
        ASN1Sequence seq = ASN1Sequence.getInstance(sign);
        byte[] r = BigIntegers.asUnsignedByteArray(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = BigIntegers.asUnsignedByteArray(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        return Arrays.concatenate(r, s);
    }

    /**
     * sm3withsm2 验签名， 默认id 1234567812345678
     * @param source
     * @param sign rs拼接签名
     * @return
     * @throws Exception
     */
    public static boolean sm3WithSm2Verify(byte[] source,byte[] sign,PublicKey publicKey) throws Exception {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, 32, 64));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        sign =  (new DERSequence(v)).getEncoded("DER");
        Signature sm3WithSM2 = Signature.getInstance("SM3WithSM2");
        sm3WithSM2.initVerify(publicKey);
        sm3WithSM2.update(source);
        return sm3WithSM2.verify(sign);
    }
    /**
     * 非标准操作 , 必须由0-9,a-z,A-Z组成的密钥
     * @return 生成 sm4 密钥， 16字节
     */
    public static byte[] genSm4Key() throws Exception{
        char[] SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
        SecureRandom  secureRandom = new SecureRandom();
        char[] buf = new char[16];

        for(int i = 0; i < 16; ++i) {
            buf[i] = SYMBOLS[secureRandom.nextInt(SYMBOLS.length)];
        }
        return new String(buf).getBytes();
    }

    /**
     * 使用sm4 ECB模式，pkcs7Padding 填充， 加密
     * @param sourceStrBytes 原文数组
     * @return 加密后的bytes数组
     */
    public static byte[] sm4Encrypt(byte[] sm4Key, byte[] sourceStrBytes) throws Exception{
        SecretKeySpec keySpec = new SecretKeySpec(sm4Key, "SM4");
        Cipher sm4 = Cipher.getInstance("SM4/ECB/PKCS7Padding",BouncyCastleProvider.PROVIDER_NAME);
        sm4.init(Cipher.ENCRYPT_MODE,keySpec);
        return sm4.doFinal(sourceStrBytes);
    }

    /**
     * 使用sm4 ECB模式，pkcs7Padding 填充， 解密
     * @param encryptedBytes sm4 加密后的bytes数组
     * @return 解密后的byte数组
     */
    public static byte[] sm4Decrypt(byte[] sm4Key, byte[] encryptedBytes) throws Exception{
        SecretKeySpec keySpec = new SecretKeySpec(sm4Key, "SM4");
        Cipher sm4 = Cipher.getInstance("SM4/ECB/PKCS7Padding",BouncyCastleProvider.PROVIDER_NAME);
        sm4.init(Cipher.DECRYPT_MODE,keySpec);
        return sm4.doFinal(encryptedBytes);
    }


    //通过sm2私钥生成公钥
    public static void genPub(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory ecKeyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decode(clientPri));
        ECPrivateKey privateKey = (ECPrivateKey)ecKeyFactory.generatePrivate(pkcs8EncodedKeySpec);
        BigInteger d = privateKey.getD();
        X9ECParameters curveParams = ECNamedCurveTable.getByName("sm2p256v1");
        ECPoint G = curveParams.getG();
        ECPoint Q = G.multiply(d);
        X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(Q, ecParameterSpec);
        PublicKey publicKey = ecKeyFactory.generatePublic(ecPublicKeySpec);
        System.out.println(Base64.toBase64String(publicKey.getEncoded()));
    }

    /**
     * 生成一对公私钥
     * @return
     * @throws Exception
     */
    public static KeyPair sm2KeyPair() throws Exception{
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ec.initialize(new ECGenParameterSpec("sm2p256v1"));
        return ec.generateKeyPair();
    }
}
