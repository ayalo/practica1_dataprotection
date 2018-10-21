package org.olaya.cybersecurity;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.*;



public class SimpleSec {

    String filePath =null;
    String fileENCRYPTED=""; // para el decript y no sobreescribir
    String destinationFileDECRYPTED=""; // para el decript y no sobreescribir


    public void  call (String command, String sourceFile, String destinationFile )throws Exception {
        if (command.equals("g")) {
            filePath=sourceFile;
            KeyPair pair=getPairKeys();

        } else if (command.equals("e")) {
            filePath=sourceFile;
            destinationFile=destinationFile;
            //if [pair == null ]  --> tratar
            getENCText(filePath, destinationFile);

        } else if (command.equals("d")) {
            fileENCRYPTED=sourceFile;
            destinationFileDECRYPTED=destinationFile;

            //if [pair == null ]  --> tratar
            getDECText(fileENCRYPTED,destinationFileDECRYPTED);

        }else System.out.println("Debes introducir bien los parametros");


    }


    public KeyPair  getPairKeys ( ) throws Exception{

        RSALibrary rsa = new RSALibrary();      // Practica 2
        KeyPair pair=null;
        //String to hold the name of the private key file.

        try {
            byte [] passPhrase = giveMePassphrase();
            pair= rsa.getKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            System.out.println("getPairKeys - PrivateKey Created ");

            FileOutputStream privateFile = new FileOutputStream(rsa.PRIVATE_KEY_FILE);
            privateFile.write(encriptPrivateKey(privateKey.getEncoded(),passPhrase));
            System.out.println("getPairKeys - Saved PrivateKey encrypted with passphrase ");

            // Establish publicKey in file PUBLIC_KEY_FILE
            PublicKey publicKey = pair.getPublic();
            FileOutputStream publicFile = new FileOutputStream(rsa.PUBLIC_KEY_FILE);
            publicFile.write(publicKey.getEncoded());
            System.out.println("getPairKeys - PublicKey Created ");


        }catch(Exception e){
            System.out.println("getPairKeys -  Exception  "+e.getMessage()+"   message  ") ;
            e.printStackTrace();
        }
        return pair;
    }

    /*************************************************************************************/
    /* Method  encriptPrivateKey*/
    /*************************************************************************************/
    public byte []  encriptPrivateKey( byte [] privateKeyByte, byte [] passphraseByte ) throws Exception {
        SymmetricCipher sc= new SymmetricCipher();
        byte [] privKeyEncript = sc.encryptCBC(privateKeyByte,passphraseByte);
        return privKeyEncript;
    }

    /*************************************************************************************/
    /* Method  decriptPrivateKey */
    /*************************************************************************************/
    public byte []  decriptPrivateKey( String PRIVATE_KEY_FILE_ENCRYPTED, byte [] passphraseByte , String pathSalida) throws Exception {
        SymmetricCipher sc= new SymmetricCipher();
        Path privateKeyPath= Paths.get(PRIVATE_KEY_FILE_ENCRYPTED);
        byte [] privateKeyDECByte = Files.readAllBytes(privateKeyPath);
        byte [] privKeyDEncrypt = sc.decryptCBC(privateKeyDECByte,passphraseByte);
        return privKeyDEncrypt;
    }

    public void getENCText(String sourceFile,String destinationFile) {

        RSALibrary rsa = new RSALibrary(); // Practica 2
        SymmetricCipher sc= new SymmetricCipher();  // Practica 1

        // Establish random sessionKey
        SecureRandom r = new SecureRandom();
        byte[] sessionKey = new byte[16];
        r.nextBytes(sessionKey);

        try {

            // Cipher plaintext input encrypted with SessionKey
            byte[] encryptedPlainText = sc.encryptCBC(readFile(sourceFile), sessionKey);

            // SessionKey encrypted with publicKey
            byte[] sessionKeyEncrypted= rsa.encrypt(sessionKey, getPublicKey(rsa.PUBLIC_KEY_FILE));

            // PrivateKey Decrypted
            PrivateKey privateKeyDEC = getPrivateKeyDECRYPTED("privateKeyDECRYPTED.key");

            //Concat encryptedPlainText and sessionKeyEncrypted
            byte [] finalEncryptedFile =new byte[encryptedPlainText.length + sessionKeyEncrypted.length]; // por ser RSA 1024 la firma ocupa eso
            System.arraycopy(encryptedPlainText, 0, finalEncryptedFile, 0, encryptedPlainText.length);
            System.arraycopy(sessionKeyEncrypted, 0, finalEncryptedFile, encryptedPlainText.length, sessionKeyEncrypted.length);
            //Concat signature
            byte [] signature= rsa.sign(finalEncryptedFile,privateKeyDEC);
            byte [] fileSigned=new byte [finalEncryptedFile.length+signature.length];
            System.arraycopy(finalEncryptedFile, 0, fileSigned, 0, finalEncryptedFile.length);
            System.arraycopy(signature, 0, fileSigned, finalEncryptedFile.length, signature.length);

            FileOutputStream destFileOutput = new FileOutputStream(destinationFile);
            destFileOutput.write(fileSigned);
            destFileOutput.close();
            System.out.println("getENCText - PlaintText encripted : "+destinationFile);


        }catch (Exception e) { e.printStackTrace();}


    }
    /*************************************************************************************/
    /* Method giveMePassphrase from keypad */
    /*************************************************************************************/
    public byte [] giveMePassphrase ( ) throws Exception{
        // Hacer que si la password es mas pequeña se rellene con otros caracteres hasta 16 y ocultarla
        System.out.println("Method giveMePassphrase -  Give the passphrase:");

        BufferedReader readpassph = new BufferedReader(new InputStreamReader(System.in));
        String passph = readpassph.readLine();
        System.out.println("Method giveMePassphrase -  Qué vale passph: " + passph.toString());
        if (!checkPassprhase((byte [])passph.getBytes())){
            System.out.println("Method giveMePassphrase -  Execute again the program with a new passphrase.");
            System.exit(1);
        }

        return passph.getBytes();

    }


    // devuelte texto session y firma byte [][]  -> Al final no la uso
/**    public byte [][]  extract (String fileENCRYPTED) {

        byte[][] extracted = new byte[3][];
        byte [] sourceBytes=null;
        Path fileENCRYPTEDPath= Paths.get(fileENCRYPTED);
        try {
            sourceBytes = Files.readAllBytes(fileENCRYPTEDPath);
        }catch (Exception e) { e.printStackTrace();}

        System.out.println("extract -  publicKey.lenght : " + pair.getPublic().getEncoded().length);
        System.out.println("extract -  sourceBytes of fileENCRYPTED.lenght : " + sourceBytes.length);

        System.out.println("extract -  Indice que se va ahora  desde 0 hasta : " + (sourceBytes.length-128-128));

        byte [] encryptedPlainText = Arrays.copyOfRange(sourceBytes,0, sourceBytes.length-128-128); //Suponemos firma y ENCsessionKey+publicKey.length =128each
        System.out.println("extract -  Extracting encryptedPlainText .lenght : " + encryptedPlainText.length);
        System.out.println("extract -  Extracting encryptedPlainText.length : " +(encryptedPlainText.length)+" hasta "+(encryptedPlainText.length+127));

        System.out.println("extract -  Extracting sourceBytes.length-128 : " +(sourceBytes.length-128)+" hasta "+sourceBytes.length );
        byte [] signature = Arrays.copyOfRange(sourceBytes, sourceBytes.length-128, sourceBytes.length);
        System.out.println("extract -  Extracting signature .lenght : " + signature.length);

        byte [] sessionKeyEncrypted= Arrays.copyOfRange(sourceBytes,encryptedPlainText.length, encryptedPlainText.length+127);
        System.out.println("extract -  Extracting sessionKeyEncrypted .lenght : " + sessionKeyEncrypted.length);

        // byte [] sesssion_key = pair.getPublic().getEncoded().length;
        extracted [0]= encryptedPlainText;
        extracted [1]= sessionKeyEncrypted;
        extracted [2]= signature;

        return extracted;
    }
*/
    public PrivateKey getPrivateKeyDECRYPTED (String path) {
        RSALibrary rsa = new RSALibrary();      // Practica 2

        String pathSalida = path;
        PrivateKey privateKeyDEC=null;
        try{
            System.out.println("getPrivateKeyDECRYPTED - Decrypting privateKey  : ");

            byte[] privKeyDEncrypt = decriptPrivateKey(rsa.PRIVATE_KEY_FILE, giveMePassphrase(), pathSalida);

            KeyFactory keyFactory = KeyFactory.getInstance(rsa.ALGORITHM);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyDEncrypt);
            privateKeyDEC = keyFactory.generatePrivate(privateKeySpec);

            // Luego la escribo en un fichero por si acaso
           /** FileOutputStream privateFileAfterDEC = new FileOutputStream(pathSalida);
            privateFileAfterDEC.write(privKeyDEncrypt);
            */
        }catch(Exception e){ e.printStackTrace(); System.exit(1);}

        return privateKeyDEC;

    }

    public PublicKey getPublicKey(String filename)
            throws Exception {
        RSALibrary rsa = new RSALibrary();      // Practica 2
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(rsa.ALGORITHM);
        return kf.generatePublic(spec);
    }

    public void getDECText( String fileENCRYPTED,String destinationFileDECRYPTED) {
        RSALibrary rsa = new RSALibrary();      // Practica 2
        SymmetricCipher sc= new SymmetricCipher();  // Practica 1
        byte[] sourceBytes = null;
        Path fileENCRYPTEDPath = Paths.get(fileENCRYPTED);
        try {
            sourceBytes = Files.readAllBytes(fileENCRYPTEDPath);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        byte[] signature = Arrays.copyOfRange(sourceBytes, sourceBytes.length - 128, sourceBytes.length);
        byte[] fileSigned = Arrays.copyOfRange(sourceBytes, 0, sourceBytes.length - 128);

        System.out.println("getDECText-  Verificamos firma  ");
        //    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {
        // Signature Verification

        /**Borrar*/
       /** KeyPair pair2=null;
        try {
            pair2 = getPairKeys();
        }catch (Exception e){e.printStackTrace();}
         System.out.println("Prueba 1 : Mensaje con Firma2 (la clave no se corresponde con la clave publica correcta) : ");
         // Verificamos Firma2. provocamos un fallo
         boolean is_OK2= rsa.verify(fileSigned,signature,pair2.getPublic());
         System.out.println("Firma2 correcta ?? :  "+is_OK2);
        */
        /**Borrar hasta aqui*/

        boolean is_OK = false;
        try{
            is_OK = rsa.verify(fileSigned, signature, getPublicKey(rsa.PUBLIC_KEY_FILE));
        }catch (Exception e){
            e.printStackTrace();
            System.exit(1);
        }
        System.out.println("getDECText-  Verifying signature  ");
        System.out.println("Signature OK ?? :  " + is_OK);
        if (!is_OK) {
            System.out.println("getDECText - Signature NOT valid. exit 1");
            System.err.println("Signature NOT valid. Verify failed.");
            System.exit(1);

        }

        //Decrypting PrivateKey
        System.out.println("getDECText-  Getting privateKey");
        PrivateKey privateKeyDEC = getPrivateKeyDECRYPTED("privateKeyDECRYPTED2.key"); // quitar path de esto para que no las genere. Mirar si lo pide

        //Decrypting the SessionKey DES Pract2
        byte[] encryptedPlainText = Arrays.copyOfRange(sourceBytes, 0, sourceBytes.length - 128 - 128); //Suponemos firma y ENCsessionKey+publicKey.length =128each

        byte [] sessionKeyEncrypted= Arrays.copyOfRange(sourceBytes,encryptedPlainText.length, encryptedPlainText.length+128);

        try{
            // Decrypting sessionKey
            byte[] sessionKeyDecrypted = rsa.decrypt(sessionKeyEncrypted, privateKeyDEC);
            System.out.println("getDECText-  Decriptin sessionKey ");

            byte[] plainTextDecrypted = sc.decryptCBC(encryptedPlainText, sessionKeyDecrypted);
            System.out.println("getDECText-  Decripting plainText ");

            // plainText to file
            FileOutputStream plainTextFile = new FileOutputStream(destinationFileDECRYPTED);
            plainTextFile.write(plainTextDecrypted);
            plainTextFile.close();
            System.out.println("getDECText-  Plaintext Decryted :  "+destinationFileDECRYPTED);

       }catch (Exception e ){ e.printStackTrace(); System.exit(1);}
    }

    /*************************************************************************************/
    /* Method checkPassprhase for check lenght of the passphrase */
    /*************************************************************************************/
    public boolean checkPassprhase ( byte [] passph) throws Exception {

        if (passph.length != 16 ) {
                System.out.println("SimpleSec - The passphrase must have 16 characters. ");
                return false;
        }
        else    return true;
    }

     /*************************************************************************************/
     /* Method arrayByteToString para convertir a char un array */
     /*************************************************************************************/
     public static String arrayByteToString ( byte[] array ){

            String out = "";
            for (byte b : array) {
                out = out + (char) b;
            }
            return out;
     }

     /*************************************************************************************/
     /* Method readfile */
     /*************************************************************************************/
     public static byte[] readFile (String file_path) throws Exception {
            FileInputStream file_stream = null;
            File file_text = new File(file_path);
            byte[] text_bytes = new byte[(int) file_text.length()];
            try {
                //text_bytes = new byte[(int) file_text.length()];
                file_stream = new FileInputStream(file_text);
                file_stream.read(text_bytes);
            } catch (IOException e) {e.printStackTrace();
            } finally {
                if (file_stream != null) {
                    try {
                        file_stream.close();
                    } catch (IOException e) {e.printStackTrace();}
                }
            }
            return text_bytes;
     }


}

