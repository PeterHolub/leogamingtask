package service;
import service.serviceconstants.ServiceConstants;
import sun.misc.BASE64Decoder;
import java.io.*;
import java.security.*;
import java.security.spec.*;

public class KeyReaderService {
    public PrivateKey getPrivateKey(File keyFile) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        FileInputStream in = new FileInputStream(keyFile);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();

        String privateKey = new String(keyBytes, ServiceConstants.UTF_8);
        privateKey = privateKey.replaceAll(ServiceConstants.PRIVATE_KEY_REGEX, "");


        BASE64Decoder decoder = new BASE64Decoder();
        keyBytes = decoder.decodeBuffer(privateKey);


        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ServiceConstants.RSA);

        return keyFactory.generatePrivate(spec);
    }


    public PublicKey getPublicKey(File keyFile) throws Exception {

        FileInputStream in = new FileInputStream(keyFile);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();

        String pubKey = new String(keyBytes, ServiceConstants.UTF_8);
        pubKey = pubKey.replaceAll(ServiceConstants.PUBLIC_KEY_REGEX, "");


        BASE64Decoder decoder = new BASE64Decoder();
        keyBytes = decoder.decodeBuffer(pubKey);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ServiceConstants.RSA);

        return keyFactory.generatePublic(spec);
    }
}