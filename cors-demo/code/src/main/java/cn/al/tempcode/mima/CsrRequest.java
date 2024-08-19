package cn.al.tempcode.mima;

import cn.al.tempcode.file.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CsrRequest {
    //C=CN,ST=广东省,L=深圳市,O=深圳农村商业银行股份有限公司,CN=www.4001961200.com
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        readCer();
        byte[][] keys = createKey();
        KeyFactory rsa = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keys[0]);
        PrivateKey privateKey = rsa.generatePrivate(pkcs8EncodedKeySpec);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keys[1]);
        PublicKey publicKey = rsa.generatePublic(x509EncodedKeySpec);

        createCsr(publicKey, new ContentSigner() {
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            final Signature signature = Signature.getInstance("SHA256withRSA");
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new DefaultSignatureAlgorithmIdentifierFinder().find(signature.getAlgorithm());
            }

            @Override
            public OutputStream getOutputStream() {
                return byteArrayOutputStream;
            }

            @Override
            public byte[] getSignature() {
                try {
                    signature.initSign(privateKey);
                    signature.update(byteArrayOutputStream.toByteArray());
                    return signature.sign();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    public static void createCsr(PublicKey publicKey, ContentSigner contentSigner) throws Exception {
        X500Name x500Name = new X500Name("CN=John Doe, OU=IT Department, O=Example Inc, C=US");
//        // 创建一个用于生成SM2密钥对的生成器
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
//        // 设置使用的SM2曲线参数
//        ECNamedCurveParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
//        keyPairGenerator.initialize(sm2Spec, new SecureRandom());
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        PublicKey aPublic = keyPair.getPublic();
////        PrivateKey aPrivate = keyPair.getPrivate();
//        Signature signature = Signature.getInstance("SM3WITHSM2", new BouncyCastleProvider());
        PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new PKCS10CertificationRequestBuilder(x500Name, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

        PKCS10CertificationRequest csr = pkcs10CertificationRequestBuilder.build(contentSigner);
        System.out.println("------------------------------------------------------------");
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(System.out));
        pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        pemWriter.flush();
    }

    public static CertificationRequest readCsr() throws Exception {
        File file = FileUtils.getFileInClassPath("wy.csr");
        CertificationRequest csr;
        try (FileReader reader = new FileReader(file)) {
            PemObject pemObject = new PemReader(reader).readPemObject();
            byte[] content = pemObject.getContent();
            ASN1InputStream asn1InputStream = new ASN1InputStream(content);
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            ASN1Sequence instance = ASN1Sequence.getInstance(asn1Primitive);
//            new PKCS10CertificationRequest(instance);
            csr = CertificationRequest.getInstance(instance);
        }
        System.out.println(csr);
        return csr;
    }

    private static byte[][] createKey() throws Exception {
        KeyPairGenerator rsaPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair keyPair = rsaPair.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
        byte[] pri = aPrivate.getEncoded();
        byte[] pub = aPublic.getEncoded();
        System.out.println("------------------------------------------------------------");
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(System.out));
        pemWriter.writeObject(new PemObject("RSA PRIVATE KEY", pri));
        pemWriter.flush();

        System.out.println("------------------------------------------------------------");
        pemWriter = new PemWriter(new OutputStreamWriter(System.out));
        pemWriter.writeObject(new PemObject("RSA PUBLIC KEY", pub));
        pemWriter.flush();
        return new byte[][]{pri, pub};
    }
    private static void readCer() throws Exception{
        File file = FileUtils.getFileInClassPath("wy.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        Certificate certificate = certificateFactory.generateCertificate(Files.newInputStream(file.toPath()));
        System.out.println(certificate);
    }
}
