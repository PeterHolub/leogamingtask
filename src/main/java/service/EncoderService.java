package service;

import org.apache.commons.codec.binary.Base64;
import service.serviceconstants.ServiceConstants;

import java.io.File;
import java.security.*;

public class EncoderService {

    private KeyReaderService keyReaderService;

    public EncoderService(KeyReaderService keyReaderService) {
        this.keyReaderService = keyReaderService;
    }

    /**
     * Подписывает строку
     *
     * @param message - Строка для подписи
     * @return подпись в Base64
     */
    public String sign(String message,File key) throws SignatureException {
        try {
            Signature sign = Signature.getInstance(ServiceConstants.SHA1_WITH_RSA);
            sign.initSign(keyReaderService.getPrivateKey(key));
            sign.update(message.getBytes(ServiceConstants.UTF_8));
            return new String(Base64.encodeBase64(sign.sign()), ServiceConstants.UTF_8);

        } catch (Exception ex) {
            throw new SignatureException(ex);
        }
    }
    /**
     * Проверяет подпись
     *
     * @param message   строка для проверки
     * @param signature подись в Base64
     * @return true если подпись верна
     * @throws SignatureException
     */
    public boolean verify(String message, String signature, File key) throws SignatureException {
        try {
            Signature sign = Signature.getInstance(ServiceConstants.SHA1_WITH_RSA);
            sign.initVerify(keyReaderService.getPublicKey(key));
            sign.update(message.getBytes(ServiceConstants.UTF_8));
            return sign.verify(Base64.decodeBase64(signature.getBytes(ServiceConstants.UTF_8)));

        } catch (Exception ex) {
            throw new SignatureException(ex);
        }
    }
}



