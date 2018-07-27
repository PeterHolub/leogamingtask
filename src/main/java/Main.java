import java.io.File;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import service.EncoderService;
import service.KeyReaderService;

public class Main {
    public static void main(String[] args) throws GeneralSecurityException {
        Main test = new Main();
        test.makeTest();

    }

    public void makeTest() throws  SignatureException {

        KeyReaderService keyReaderService = new KeyReaderService();
        EncoderService encoderService = new EncoderService(keyReaderService);

        String XmlRequest = "<request point=\"327\"> \n" +
                "<verify service=\"4390\" account=\"12345\"/> \n" +
                "</request>";

        System.out.println("Encoding request with Private Key to create signature");

        String signature = encoderService.sign(XmlRequest,new File("src/main/resources/private.pem"));

        System.out.println("Verify signature with public.pem");

        boolean check = encoderService.verify(XmlRequest, signature,new File("src/main/resources/public.pem"));

        System.out.println("Result of verification with public.pem: " + check);

        System.out.println("Verify signature with GeneratedFromPrivateKey.pem");

        boolean check2 = encoderService.verify(XmlRequest, signature,new File("src/main/resources/GeneratedFromPrivateKey.pem"));
        System.out.println("Result of verification with public.pem: " + check2);


        System.out.println("Encoding request with randomPrivate Key to create signature");

        String signature2 = encoderService.sign(XmlRequest,new File("src/main/resources/randomPrivate.pem"));
        System.out.println("Verify signature with randomPublic.pem");

        boolean check3 = encoderService.verify(XmlRequest, signature2 ,new File("src/main/resources/randomPublic.pem"));

        System.out.println("Result of verification with public.pem: " + check3);

  }
}