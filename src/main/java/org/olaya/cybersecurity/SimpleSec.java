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


public class SimpleSec {


    public void  SimpleSec () throws Exception{ //(String passphrase){//( char command, String sourceFile, String destinationFile) {

        RSALibrary rsaLibrary = new RSALibrary();       // Practica 2
        SymmetricCipher scEnc= new SymmetricCipher();  // Practica 1

        // Temporary fix passprhase
        // String passphrase = new String ("1234567890123456");

       // byte [] passphraseByte = giveMePassphrase();


        try {

            rsaLibrary.generateKeys();
            String filePrivateKey = "./private.key"; // private encriptada con la passphrase
            encriptPrivateKey(filePrivateKey,giveMePassphrase());

            String filePath = "./text.txt";
            String filePublicKey = "./public.key";
            String filePrivateKeyCiphered = "./privateCiph.key"; // private encriptada con la passphrase

            // leo clave publica
            System.out.println("SimpleSec - String plain text - input :  " + arrayByteToString(readFile(filePath)));
            // Estabish random sessionKey
            SecureRandom r = new SecureRandom();
            byte[] sessionKey = new byte[16];
            r.nextBytes(sessionKey);


            FileInputStream publicFile = new FileInputStream(filePublicKey);
            ObjectInputStream objetoPublicKey = new ObjectInputStream(publicFile);
            PublicKey publicKey = (PublicKey) objetoPublicKey.readObject();

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

            // PrivateKey
            FileInputStream privateFile = new FileInputStream(filePrivateKey);
            ObjectInputStream objetoPrivateKey = new ObjectInputStream(privateFile);
            PrivateKey privateKey = (PrivateKey) objetoPrivateKey.readObject();

            // Signature finalEncriptedFile  (Concatenation encryptedPlainText and sessionKeyEncripted)
            byte[] signature= rsaLibrary.sign(finalEncriptedFile,privateKey);
            System.out.println("SimpleSec - Mensaje con Firma :  "+signature.length);

            //public byte[] encryptCBC (byte[] input, byte[] byteKey)




        }catch(Exception e){
            System.out.println("SimpleSec -  Exception  "+e.getMessage()+"   message  ") ;
            e.printStackTrace();
        }

    }
    /*************************************************************************************/
    /* Method  from keypad */
    /*************************************************************************************/
    public void  encriptPrivateKey( String filePrivateKey, byte [] passphraseByte ) throws Exception {
        // leemos fichero clave privada como byte[]
        byte [] privateKeyByte = readFile(filePrivateKey);
        SymmetricCipher  scEnc= new SymmetricCipher();  // Practica 1
        byte [] privKeyEncript = scEnc.encryptCBC(privateKeyByte,passphraseByte);
        System.out.println( "SimpleSec -  privateKeyByte.length :  "+privKeyEncript.length);

        writeFileLine(filePrivateKey,privKeyEncript);

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
    public static  byte [] writeFileLine (String output_path,byte[] output) throws Exception {
        Path path = null;
        byte [] outputFichero= null;
        try {
            path = Paths.get(output_path);
            outputFichero = Files.readAllBytes(path);

        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return outputFichero;
    }
}

