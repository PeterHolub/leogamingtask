package service.serviceconstants;

import java.io.File;

public class ServiceConstants {
    public static final File PRIVATE_KEY_FILE = new File("src/main/resources/private.pem");
    public static final File PUBLIC_KEY_FILE = new File("src/main/resources/public.pem");
    public static final String PRIVATE_KEY_REGEX ="(-+BEGIN RSA PRIVATE KEY-+\\r?\\n|-+END RSA PRIVATE KEY-+\\r?\\n?)";
    public static final String PUBLIC_KEY_REGEX ="(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)";
    public static final String RSA ="RSA";
    public static final String UTF_8 ="UTF-8";
    public static final String SHA1_WITH_RSA ="SHA1withRSA";
}
