package cn.al.tempcode.io;


import cn.al.tempcode.mima.CryptTest;
import okhttp3.*;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

//请求构造
public class OKHttpTemplate {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * https://127.0.0.1:8212/efms/ordersubmit/V1
     * http://127.0.0.1:8212/efms/gkordersubmit/V1
     * https://127.0.0.1:8212/efms/orderquery/V1
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        //构造密钥对象
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decode(CryptTest.clientPri));
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decode(CryptTest.serverPub));
        KeyFactory ecKeyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey clientPrivateKey = ecKeyFactory.generatePrivate(pkcs8EncodedKeySpec);
        PublicKey servePublicKey = ecKeyFactory.generatePublic(x509EncodedKeySpec);
        //1.从文件读取body
        String body = readBodyFromFile("ordersubmit.json");
        //     https://127.0.0.1:8212/efms/ordersubmit/V1
        //     https://127.0.0.1:8212/efms/gkordersubmit/V1
        //     https://127.0.0.1:8212/efms/orderquery/V1
        String url = "https://127.0.0.1:8212/efms/ordersubmit/V1";
        //2.生成sm4密钥
        byte[] sm4Key = CryptTest.genSm4Key();
        //3.服务端公钥加密sm4密钥
        byte[] wwkBytes = CryptTest.sm2Encrypt(sm4Key, servePublicKey);
        //4.请求头中 wwk
        String wwk = Base64.toBase64String(wwkBytes);
        //5.请求头中 秒级timestamp
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        //6.构造签名对象
        byte[] signSource = (body + timestamp).getBytes(StandardCharsets.UTF_8);
        //7.使用客户端私钥签名
        byte[] sign = CryptTest.sm3WithSm2Sign(signSource, clientPrivateKey);
        String signStr = Base64.toBase64String(sign);
        //8.构造请求头
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "text/plain");
        headers.put("x-timestamp", timestamp);
        headers.put("x-wwk", wwk);
        headers.put("User-Agent", "Java/22.1.0 (Windows 11/10.0) Java/ 1.8.0_333 okhttp3/null");
        headers.put("x-signature", signStr);
        headers.put("Content-Type:", "text/plain; charset=utf-8");
        //9.构造加密后body
        byte[] encrypt = CryptTest.sm4Encrypt(sm4Key, body.getBytes(StandardCharsets.UTF_8));
        String encryptBody = Base64.toBase64String(encrypt);
        //10.发请求
        Response response = sendHttpsRequest(encryptBody, headers, url);
        //11.客户端解析body
        byte[] bytes = response.body().bytes();
        System.out.println("source resp body:\n"+ new String(bytes));
        byte[] encryptedBytes = Base64.decode(new String( bytes,StandardCharsets.UTF_8));
        byte[] decryptBytes = CryptTest.sm4Decrypt(sm4Key, encryptedBytes);
        String respBodyStr = new String(decryptBytes, StandardCharsets.UTF_8);
        System.out.println("decrypt resp body:\n" + respBodyStr);
        System.out.println(response.headers());
        //12.客户端使用服务端公钥验签
        String respSignStr = response.header("x-signature");
        String respTimestamp = response.header("x-timestamp");
        byte[] respSignSource = (respBodyStr + respTimestamp).getBytes(StandardCharsets.UTF_8);
        boolean b = CryptTest.sm3WithSm2Verify(respSignSource, Base64.decode(respSignStr), servePublicKey);
        System.out.println("响应验签：" + b);

        response.close();

    }

    /**
     * 发http请求， 设置了fiddler代理 127.0.0.1 8888
     *
     * @param body
     * @param headers
     * @param url
     * @return
     * @throws Exception
     */
    public static Response sendHttpsRequest(String body, Map<String, String> headers, String url) throws Exception {
        X509TrustManager x509TrustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[]{};
            }
        };
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, new X509TrustManager[]{x509TrustManager}, null);
        SSLSocketFactory socketFactory = tls.getSocketFactory();
        OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(socketFactory, x509TrustManager)
                .hostnameVerifier((s, session) -> true)
                .readTimeout(60, TimeUnit.SECONDS)
                //设置fiddler代理
                .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8888)))
                .build();
        Request.Builder builder = new Request.Builder()
                .url(url);
        //设置body
        RequestBody requestBody = RequestBody.create(MediaType.parse("text/plain"), body);
        builder.post(requestBody);
        //请求头
        headers.forEach(builder::addHeader);
        Request request = builder.build();

        return client.newCall(request).execute();
    }

    public static String readBodyFromFile(String fileName) throws Exception {
        InputStream resourceAsStream = OKHttpTemplate.class.getClassLoader().getResourceAsStream(fileName);
        String body = IOUtils.toString(resourceAsStream, StandardCharsets.UTF_8);
        resourceAsStream.close();
        return body;
    }
}
