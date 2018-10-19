package org.olaya.cybersecurity;

import java.io.*;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.ObjectOutputStream;



public class SimpleSec {


    public void  SimpleSec () throws Exception{ //(String passphrase){//( char command, String sourceFile, String destinationFile) {

        RSALibrary rsaLibrary = new RSALibrary();       // Practica 2
        SymmetricCipher scEnc= new SymmetricCipher();  // Practica 1
        //String to hold the name of the private key file.

        String PRIVATE_KEY_FILE_ENCRIPTED = rsaLibrary.PRIVATE_KEY_FILE;
        String PUBLIC_KEY_FILE = rsaLibrary.PUBLIC_KEY_FILE;
        String filePath = "";  // Where the file to storage encripted is
///Users/olaya/IdeaProjects/practica1_dataprotection/text.txt
        String pathSalida = "./privateKeyDECRIPTED.key";


        try {

    /**        System.out.println("SimpleSec - Generamos las claves :");
            rsaLibrary.generateKeys();
            String filePrivateKey = "./private.key"; // Acordanos de borrar este
            String pathPrivateKeySalida = "./private_salida.key"; // private encriptada con la passphrase
            String pathDecriptedPrivateKeySalida = "./private_Decripted.key"; // private encriptada con la passphrase

            byte [] PrivateKey =writePKey(filePrivateKey);
            System.out.println("SimpleSec - Salida = "+Arrays.toString(PrivateKey));
            System.out.println("SimpleSec - Encriptamos clave privada con passphrase : se genera private_salida.key");
            encriptPrivateKey(PrivateKey,pathPrivateKeySalida,giveMePassphrase());
            System.out.println("SimpleSec - Desencriptamos clave privada :");
            byte [] SALIDA=decriptPrivateKey(pathPrivateKeySalida,giveMePassphrase(),pathDecriptedPrivateKeySalida);
            System.out.println("SimpleSec - Salida DECRIPT= "+Arrays.toString(SALIDA));


*/
            byte [] passPhrase = giveMePassphrase();
            System.out.println("SimpleSec - Generamos clave privada :");
            KeyPair pair= rsaLibrary.getKeyPair();
            PrivateKey privateKey = pair.getPrivate();

            // TO-DO: store the private key in the file PRIVATE_KEY_FILE_ENCRIPTED
            // ...
            FileOutputStream privateFile = new FileOutputStream(PRIVATE_KEY_FILE_ENCRIPTED);
           //1// ObjectOutputStream objetoPrivateKey= new ObjectOutputStream(privateFile);
            System.out.println("SimpleSec - Guardamos clave privada encriptada con la passphrase ");
            //1//((ObjectOutputStream) objetoPrivateKey).writeObject(encriptPrivateKey(privateKey.getEncoded(),giveMePassphrase()));
            privateFile.write(encriptPrivateKey(privateKey.getEncoded(),passPhrase));
            // Prueba to decript la clave privada.
            //public void  decriptPrivateKey( String PRIVATE_KEY_FILE_ENCRIPTED, byte [] passphraseByte , String pathSalida) throws Exception {
            System.out.println("SimpleSec - Desencriptamos la privateKey para ver si queda igual : ");
            byte [] salidaDECPrivKey = decriptPrivateKey(PRIVATE_KEY_FILE_ENCRIPTED,giveMePassphrase(),pathSalida);
            System.out.println("SimpleSec - Que vale salidaDECPrivKey : "+arrayByteToString(privateKey.getEncoded()));
            System.out.println("SimpleSec - Son iguales  : "+Arrays.equals(salidaDECPrivKey,privateKey.getEncoded()));




// hacer el programa para encriptar cogiendo por teclado lo que se quiere hacer
            //  y para despues nueva ejecución o continuación desencriptar
/**
            // Establish random sessionKey
            SecureRandom r = new SecureRandom();
            byte[] sessionKey = new byte[16];
            r.nextBytes(sessionKey);

            // Establish publicKey in file PUBLIC_KEY_FILE
            PublicKey publicKey = pair.getPublic();
            FileOutputStream publicFile = new FileOutputStream(PUBLIC_KEY_FILE);
            ObjectOutputStream objetoPublicKey = new ObjectOutputStream(publicFile);
            ((ObjectOutputStream)objetoPublicKey).writeObject(publicKey);
            publicFile.close();


            filePath =giveMeTextFile();
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

            System.out.println("SimpleSec -  Array sin pad antes de retur decript: " +finalEncriptedFile.length);
*/
            // PrivateKey
           /** FileInputStream privateFile = new FileInputStream(filePrivateKey);
            ObjectInputStream objetoPrivateKey = new ObjectInputStream(privateFile);
            PrivateKey privateKey = (PrivateKey) objetoPrivateKey.readObject();

            // Signature finalEncriptedFile  (Concatenation encryptedPlainText and sessionKeyEncripted)
            byte[] signature= rsaLibrary.sign(finalEncriptedFile,privateKey);
            System.out.println("SimpleSec - Mensaje con Firma :  "+signature.length);

            //public byte[] encryptCBC (byte[] input, byte[] byteKey)
*/



        }catch(Exception e){
            System.out.println("SimpleSec -  Exception  "+e.getMessage()+"   message  ") ;
            e.printStackTrace();
        }

    }
    /*************************************************************************************/
    /* Method  encriptPrivateKey*/
    /*************************************************************************************/
    public byte []  encriptPrivateKey( byte [] privateKeyByte, byte [] passphraseByte ) throws Exception {
        SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
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

        SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
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
    public String giveMeTextFile ( ) throws Exception{
        // Hacer que si la password es mas pequeña se rellene con otros caracteres hasta 16

        System.out.println("SimpleSec -  Give the text file that you want to storage safe [ ex. /path_where_the_file_is/text_to_save.txt ]  :");
        BufferedReader readFile = new BufferedReader(new InputStreamReader(System.in));
        String file = readFile.readLine();

        return file;

    }
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


}

