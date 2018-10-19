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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;



public class SimpleSec {

    RSALibrary rsaLibrary = new RSALibrary();      // Practica 2
    SymmetricCipher scEnc= new SymmetricCipher();  // Practica 1
    KeyPair pair =null;
    String filePath =null;
    String claveprivada = "./private_original.key"; //BORRAR
    String pathSalida = "./privateKeyDECRIPTED.key"; //BORRAR
    String pathSalidaBACK = "./privateKeyDECRIPTEDBACK.key"; //Borrar
    String destinationFile="";


    public void  call (String command, String sourceFile, String destinationFile )throws Exception {

        if (command == "g") {

            filePath="./"+sourceFile;
            pair=getPairKeys();

        } else if (command == "e") {
            filePath="./"+sourceFile;
            destinationFile="./"+destinationFile;
            getENCText(filePath, destinationFile,pair);

        } else if (command == "d") {
            // getDECText(sourceFile, destinationFile);
        }else System.out.println("Debes introducir bien los parametros");


    }

    public KeyPair  getPairKeys ( ) throws Exception{

        //String to hold the name of the private key file.
/**
        String PRIVATE_KEY_FILE_ENCRIPTED = rsaLibrary.PRIVATE_KEY_FILE;
        String PUBLIC_KEY_FILE = rsaLibrary.PUBLIC_KEY_FILE;
        String filePath = "./"+sourceFile;  // Where the file to storage encripted is
        String pathSalida = "./privateKeyDECRIPTED.key";
        String claveprivada = "./private_original.key";
*/
        try {
            byte [] passPhrase = giveMePassphrase();
            System.out.println("SimpleSec - Generamos clave privada :");
            pair= rsaLibrary.getKeyPair(); // ESTA DEFINIDA ARRIBA
            PrivateKey privateKey = pair.getPrivate();

            FileOutputStream privateFile = new FileOutputStream(rsaLibrary.PRIVATE_KEY_FILE);
            //1// ObjectOutputStream objetoPrivateKey= new ObjectOutputStream(privateFile);
            System.out.println("SimpleSec - Guardamos clave privada encriptada con la passphrase ");
            //1//((ObjectOutputStream) objetoPrivateKey).writeObject(encriptPrivateKey(privateKey.getEncoded(),giveMePassphrase()));
            privateFile.write(encriptPrivateKey(privateKey.getEncoded(),passPhrase));


            //BORRAR DESDE AQUI
            FileOutputStream fichero_original = new FileOutputStream(claveprivada);
            fichero_original.write(privateKey.getEncoded());
            //ObjectOutputStream objetoPrivateKey_original= new ObjectOutputStream(fichero_original);
            //((ObjectOutputStream) objetoPrivateKey_original).writeObject(privateKey);

            // BORRAR Prueba to decript la clave privada.
            //public void  decriptPrivateKey( String PRIVATE_KEY_FILE_ENCRIPTED, byte [] passphraseByte , String pathSalida) throws Exception {
            System.out.println("SimpleSec - Desencriptamos la privateKey para ver si queda igual : ");
            byte [] privKeyDEncript = decriptPrivateKey(rsaLibrary.PRIVATE_KEY_FILE,giveMePassphrase(),pathSalidaBACK);
             System.out.println("SimpleSec - Que vale salidaDECPrivKey : "+arrayByteToString(privateKey.getEncoded()));
            System.out.println("SimpleSec - Son iguales  : "+Arrays.equals(privKeyDEncript,privateKey.getEncoded()));
            FileOutputStream privateFileAfterDEC = new FileOutputStream(pathSalidaBACK);
            privateFileAfterDEC.write(privKeyDEncript);
            //BORRAR HASTA AQUI


        // hacer el programa para encriptar cogiendo por teclado lo que se quiere hacer
            //  y para despues nueva ejecución o continuación desencriptar


        }catch(Exception e){
            System.out.println("SimpleSec -  Exception  "+e.getMessage()+"   message  ") ;
            e.printStackTrace();
        }
        return pair;
    }
/**
    public void getENCText(String sourceFile,String destinationFile) throws Exception{
        if ( pair != null) {
            getENCTextPair(sourceFile, destinationFile, pair);
        }else {
            System.out.println(" No has generado las Claves Publica y Privada");
            System.out.println(" Generando claves para poder encriptar : ");
            filePath="./"+sourceFile;
            PRIVATE_KEY_FILE_ENCRIPTED=rsaLibrary.PRIVATE_KEY_FILE;
            PUBLIC_KEY_FILE = rsaLibrary.PUBLIC_KEY_FILE;
            pair=this.getPairKeys();

        }
    }
*/
    public void getENCText(String sourceFile,String destinationFile,KeyPair pair) {

        String filePath = "./"+sourceFile;
        // Establish random sessionKey
        SecureRandom r = new SecureRandom();
        byte[] sessionKey = new byte[16];
        r.nextBytes(sessionKey);
        try {
            // Establish publicKey in file PUBLIC_KEY_FILE
            PublicKey publicKey = pair.getPublic();
            FileOutputStream publicFile = new FileOutputStream(rsaLibrary.PUBLIC_KEY_FILE);
            publicFile.write(publicKey.getEncoded());
        /**FileOutputStream publicFile = new FileOutputStream(PUBLIC_KEY_FILE);
         ObjectOutputStream objetoPublicKey = new ObjectOutputStream(publicFile);
         ((ObjectOutputStream)objetoPublicKey).writeObject(publicKey);
         publicFile.close();
         */

        System.out.println("SimpleSec - fichero a guardar en disco :");
        // filePath =giveMeTextFile();
        System.out.println("String plain text - input :  "+arrayByteToString(readFile(filePath)));

        // Cipher plaintext input encripted with SessionKey
        byte[] encryptedPlainText = scEnc.encryptCBC(readFile(filePath), sessionKey);
        System.out.println("SimpleSec - String plaintext encripted with sessionKey length: "+encryptedPlainText.length);

        // SesionKey encripted with publicKey
        byte[] sessionKeyEncripted= rsaLibrary.encrypt(sessionKey, publicKey);
        System.out.println("SimpleSec - SessionKey encripted with publicKey length: " + sessionKeyEncripted.length);

        //Concatenation encryptedPlainText and sessionKeyEncripted
        byte [] finalEncriptedFile =new byte[encryptedPlainText.length + sessionKeyEncripted.length];
        System.arraycopy(encryptedPlainText, 0, finalEncriptedFile, 0, encryptedPlainText.length);
        System.arraycopy(sessionKeyEncripted, 0, finalEncriptedFile, encryptedPlainText.length, sessionKeyEncripted.length);

        System.out.println("SimpleSec -  Array sin pad antes de return decript: " +finalEncriptedFile.length);

        // PrivateKey Desencript

        System.out.println("SimpleSec - Desencriptamos la privateKey para ver si queda igual : ");
        String pathSalida = "./privateKeyDECRIPTED.key";
        byte [] privKeyDEncript = decriptPrivateKey(rsaLibrary.PRIVATE_KEY_FILE,giveMePassphrase(),pathSalida);
        System.out.println("SimpleSec - Que vale salidaDECPrivKey : "+arrayByteToString(privKeyDEncript));

            KeyFactory keyFactory = KeyFactory.getInstance(rsaLibrary.ALGORITHM);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyDEncript);
            PrivateKey privateKeyDEC = keyFactory.generatePrivate(privateKeySpec);

            // Luego la escribo en un fichero por si acaso
        FileOutputStream privateFileAfterDEC = new FileOutputStream(pathSalida);
        privateFileAfterDEC.write(privKeyDEncript);

/** NO FUNCIONA
            ByteArrayInputStream bais = new ByteArrayInputStream(privKeyDEncript);
            ObjectInput aux = new ObjectInputStream(bais);
            PrivateKey privateKeyDEC = (PrivateKey) aux.readObject();

*/

        System.out.println("Calculamos Firma---  ");
        // Signature finalEncriptedFile  (Concatenation encryptedPlainText and sessionKeyEncripted)
        byte [] fileSigned= rsaLibrary.sign(finalEncriptedFile,privateKeyDEC);
        System.out.println("Longitud Firma :  "+fileSigned.length);

        // Guardo fichero con la firma
        //    public static void writeFile (String output_path,byte[] output) throws Exception {
        writeFile(destinationFile,fileSigned);

        }catch (Exception e) { e.printStackTrace();}


    }

    /*************************************************************************************/
    /* Method  encriptPrivateKey*/
    /*************************************************************************************/
    public byte []  encriptPrivateKey( byte [] privateKeyByte, byte [] passphraseByte ) throws Exception {
        //SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
        byte [] privKeyEncript = scEnc.encryptCBC(privateKeyByte,passphraseByte);
        System.out.println("SimpleSec - privateKeyByte.length = "+privateKeyByte.length);
        System.out.println( "SimpleSec -  privateKeyByte.length CON PAD :  "+privKeyEncript.length);
        return privKeyEncript;
    }

    /*************************************************************************************/
    /* Method  decriptPrivateKey */
    /*************************************************************************************/
    public byte []  decriptPrivateKey( String PRIVATE_KEY_FILE_ENCRIPTED, byte [] passphraseByte , String pathSalida) throws Exception {
        // leemos fichero clave privada como byte[]

        //SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
        //byte [] privateKeyDECByte = readFile(PRIVATE_KEY_FILE_ENCRIPTED);
        Path privateKeyPath= Paths.get(PRIVATE_KEY_FILE_ENCRIPTED);
        byte [] privateKeyDECByte = Files.readAllBytes(privateKeyPath);
        byte [] privKeyDEncript = scEnc.decryptCBC(privateKeyDECByte,passphraseByte);
        System.out.println( "SimpleSec -  privKeyDECRIPTED.length :  "+privKeyDEncript.length);
        System.out.println( "SimpleSec -  privKeyDECRIPTED.toString :  "+arrayByteToString(privKeyDEncript));
        /**
        ByteArrayInputStream bai = new ByteArrayInputStream(privKeyDEncript);
        ObjectInput aux = new ObjectInputStream(bai);
        PrivateKey privateKeyDecripted = (PrivateKey) aux.readObject();
        */
        //writeFile(pathSalida,privKeyDEncript);
        return privKeyDEncript;//privateKeyDecripted;
    }


    /*************************************************************************************/
    /* Method giveMePassphrase from keypad */
    /*************************************************************************************/
    public byte [] giveMePassphrase ( ) throws Exception{
        // Hacer que si la password es mas pequeña se rellene con otros caracteres hasta 16

        System.out.println("SimpleSec -  Give the passphrase:");
        BufferedReader readpassph = new BufferedReader(new InputStreamReader(System.in));
        String passph = readpassph.readLine();
        System.out.println("SimpleSec -  Qué vale passph: " + passph.toString());
        if (!checkPassprhase((byte [])passph.getBytes())){
             System.out.println("SimpleSec -  Execute again the program with a new passphrase.");
             System.exit(1);
        }

        return passph.getBytes();

    }
    /*************************************************************************************/
    /* Method giveMeTextFile to save encripted from keypad */
    /*************************************************************************************/
    /**   public String giveMeTextFile ( ) throws Exception{
        // Hacer que si la password es mas pequeña se rellene con otros caracteres hasta 16


        System.out.println("SimpleSec -  Give the text file that you want to storage safe [ ex. /path_where_the_file_is/text_to_save.txt ]  :");
        BufferedReader outputFile =null; //= new BufferedReader(new InputStreamReader(System.in));
        String file=null;
        try {

            outputFile = new BufferedReader(new InputStreamReader(System.in));

            //while ((file = outputFile.readLine()) != null) {
            System.out.println("incializando text.txt";
                file=outputFile.readLine();
           // }

        } catch (IOException e) { e.printStackTrace();
        } finally {
            try {
                if (outputFile != null)outputFile.close();
            } catch (IOException ex) { ex.printStackTrace(); }
        }

        return file;


    }*/
    /*************************************************************************************/
    /* Method checkPassprhase for check lenght of the passphrase */
    /*************************************************************************************/
    public boolean checkPassprhase ( byte [] passph) throws Exception {

        if (passph.length != 16 ) {
                System.out.println("SimpleSec - The passphrase must have 16 characters. ");
                return false;
        }
        else
            return true;
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
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (file_stream != null) {
                    try {
                        file_stream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            return text_bytes;
     }


     /*************************************************************************************/
     /* Method writefile */
     /*************************************************************************************/
     public static void writeFile (String output_path,byte[] output) throws Exception {
            Writer writer = null;

            try {
                writer = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(output_path), "US-ASCII"));
                writer.write(arrayByteToString(output));
            } catch (IOException ex) {
            } finally {
                try {
                    writer.close();
                } catch (Exception ex) {
                }
            }
     }
     /*************************************************************************************/
     /* Method writefile por lineas  */
     /*************************************************************************************/
     /**    public static byte [] writePKey(String output_path) throws Exception {
        Path path = null;
        byte [] bytePKey= null;
        try {
            path = Paths.get(output_path);
            bytePKey= Files.readAllBytes(path);

        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return bytePKey;
     }*/

     /*************************************************************************************/
     /* Method  from keypad origin*/
     /*************************************************************************************/
     /**  public void  encriptPrivateKey( String filePrivateKey, byte [] passphraseByte ) throws Exception {
     // leemos fichero clave privada como byte[]
     byte [] privateKeyByte = readFile(filePrivateKey);
     SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
     byte [] privKeyEncript = scEnc.encryptCBC(privateKeyByte,passphraseByte);
     System.out.println( "SimpleSec -  privateKeyByte.length :  "+privKeyEncript.length);

     writeFile(filePrivateKey,privKeyEncript);

     }*/
     /*************************************************************************************/
     /* Method  from keypad */ //rallada
     /*************************************************************************************/
     /**  public void  encriptPrivateKey( byte [] privateKeyByte,String path, byte [] passphraseByte ) throws Exception {
     // leemos fichero clave privada como byte[]

     // byte [] privateKeyByte = readFile(filePrivateKey);
     SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
     byte [] privKeyEncript = scEnc.encryptCBC(privateKeyByte,passphraseByte);
     System.out.println( "SimpleSec -  privateKeyByte.length :  "+privKeyEncript.length);

     writeFile(path,privKeyEncript);

     }*/
     /*************************************************************************************/
     /* Method  from keypad */
     /*************************************************************************************/
     /**   public void  decriptPrivateKey( String pathPrivateKeyByteENC, byte [] passphraseByte , String pathSalida) throws Exception {
     // leemos fichero clave privada como byte[]

     byte [] privateKeyDECByte = readFile(pathPrivateKeyByteENC);
     SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
     byte [] privKeyDEncript = scEnc.decryptCBC(privateKeyDECByte,passphraseByte);
     System.out.println( "SimpleSec -  privKeyDEncript.length :  "+privKeyDEncript.length);

     writeFile(pathSalida,privKeyDEncript);

     }*/

    /*************************************************************************************/
    /* Method  decriptPrivateKey  a borrar. funciona */
    /*************************************************************************************/
    /**    public byte []  decriptPrivateKey( String PRIVATE_KEY_FILE_ENCRIPTED, byte [] passphraseByte , String pathSalida) throws Exception {
        // leemos fichero clave privada como byte[]

        SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
        //byte [] privateKeyDECByte = readFile(PRIVATE_KEY_FILE_ENCRIPTED);
        Path privateKeyPath= Paths.get(PRIVATE_KEY_FILE_ENCRIPTED);
        byte [] privateKeyDECByte = Files.readAllBytes(privateKeyPath);
        byte [] privKeyDEncript = scEnc.decryptCBC(privateKeyDECByte,passphraseByte);
        System.out.println( "SimpleSec -  privKeyDECRIPTED.length :  "+privKeyDEncript.length);
        System.out.println( "SimpleSec -  privKeyDECRIPTED.toString :  "+arrayByteToString(privKeyDEncript));
    */
    /**
        ByteArrayInputStream bai = new ByteArrayInputStream(privKeyDEncript);
        ObjectInput aux = new ObjectInputStream(bai);
        PrivateKey privateKeyDecripted = (PrivateKey) aux.readObject();
    */
    /**      //writeFile(pathSalida,privKeyDEncript);
        return privKeyDEncript;//privateKeyDecripted;
    }

    */
  /**  private static void copyFile(File source, File dest) throws IOException {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = new FileInputStream(source);
            os = new FileOutputStream(dest);
            byte[] buffer = new byte[1024];
            int length;
            while ((length = is.read(buffer)) > 0) {
                os.write(buffer, 0, length);
            }
        } finally {
            is.close();
            os.close();
        }
    }
   */
}

