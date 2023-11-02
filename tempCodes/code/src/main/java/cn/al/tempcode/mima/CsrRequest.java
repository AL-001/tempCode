package cn.al.tempcode.mima;

import cn.al.tempcode.file.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.security.*;

public class CsrRequest {
    public static void main(String[] args) throws Exception {
        createCsr();
        System.out.println("....");
    }

    public static CertificationRequest createCsr() throws Exception {
        X500Name x500Name = new X500Name("CN=John Doe, OU=IT Department, O=Example Inc, C=US");
        // 创建一个用于生成SM2密钥对的生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 设置使用的SM2曲线参数
        ECNamedCurveParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        keyPairGenerator.initialize(sm2Spec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        Signature signature = Signature.getInstance("SM3WITHSM2", new BouncyCastleProvider());
        PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new PKCS10CertificationRequestBuilder(x500Name, SubjectPublicKeyInfo.getInstance(aPublic.getEncoded()));
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PKCS10CertificationRequest csr = pkcs10CertificationRequestBuilder.build(new ContentSigner() {
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
                    signature.initSign(aPrivate);
                    signature.update(byteArrayOutputStream.toByteArray());
                    return signature.sign();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        PemWriter pemWriter = new PemWriter(new PrintWriter(System.out));
        pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST",csr.getEncoded()));
        return null;
    }

    public static CertificationRequest readCsr() throws Exception {
        File file = FileUtils.getFileInClassPath("yqzl.csr");
        CertificationRequest csr = null;
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
}
