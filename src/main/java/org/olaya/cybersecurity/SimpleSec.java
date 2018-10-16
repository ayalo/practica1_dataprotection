package org.olaya.cybersecurity;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;


public class SimpleSec {


    public void  SimpleSec (){//( char command, String sourceFile, String destinationFile) {

        RSALibrary rsaLibrary = new RSALibrary();

        try {

            rsaLibrary.generateKeys();

            String filePath = "/Users/olaya/IdeaProjects/practica1_dataprotection/text.txt";
            String filePublicKey = "/Users/olaya/IdeaProjects/practica1_dataprotection/public.key";
            String filePrivateKey = "/Users/olaya/IdeaProjects/practica1_dataprotection/private.key"; // private encriptada con la passphrase
            String filePrivateKeyCiphered = "/Users/olaya/IdeaProjects/practica1_dataprotection/privateCiph.key"; // private encriptada con la passphrase

            // leo clave publica
            System.out.println("  String plain text - input :  " + arrayByteToString(readFile(filePath)));

            SecureRandom r = new SecureRandom();
            byte[] sessionKey = new byte[16];
            r.nextBytes(sessionKey);

            String passphrase = new String ("1234567890123456");
            byte [] passphraseByte = passphrase.getBytes();

            SymmetricCipher  scEnc= new SymmetricCipher();


            FileInputStream publicFile = new FileInputStream(filePublicKey);
            ObjectInputStream objetoPublicKey = new ObjectInputStream(publicFile);
            PublicKey publicKey = (PublicKey) objetoPublicKey.readObject();


            // Cipher plaintext input encripted with SessionKey
            byte[] encryptedPlainText = scEnc.encryptCBC(readFile(filePath), sessionKey);
            System.out.println("String plaintext encripted with sessionKey :"+Arrays.toString(encryptedPlainText));

            // SesionKey encripted with publicKey
            byte[] sessionKeyEncripted= rsaLibrary.encrypt(sessionKey, publicKey);
            System.out.println("sessionKey encripted with publicKey" + Arrays.toString(sessionKeyEncripted));

            //Concatenation encryptedPlainText and sessionKeyEncripted
            byte [] finalEncriptedFile =new byte[encryptedPlainText.length + sessionKeyEncripted.length];
            System.arraycopy(encryptedPlainText, 0, finalEncriptedFile, 0, encryptedPlainText.length);
            System.arraycopy(sessionKeyEncripted, 0, finalEncriptedFile, encryptedPlainText.length, sessionKeyEncripted.length);

            System.out.println(" Array sin pad antes de retur decript:" +Arrays.toString(finalEncriptedFile));

            // PrivateKey
            FileInputStream privateFile = new FileInputStream(filePrivateKey);
            ObjectInputStream objetoPrivateKey = new ObjectInputStream(privateFile);
            PrivateKey privateKey = (PrivateKey) objetoPrivateKey.readObject();

            // Signature finalEncriptedFile  (Concatenation encryptedPlainText and sessionKeyEncripted)
            byte[] signature= rsaLibrary.sign(finalEncriptedFile,privateKey);
            System.out.println("Mensaje con Firma :  "+arrayByteToString(signature));


            //public byte[] encryptCBC (byte[] input, byte[] byteKey)

            // leemos fichero clave privada como byte[]
            byte [] privateKeyByte = readFile(filePrivateKey);
            System.out.println( " privateKeyByte:  "+arrayByteToString(privateKeyByte));
            System.out.println( " privateKeyByte.lengt :"+ privateKeyByte.length);
            System.out.println( " sessionKey :"+ arrayByteToString(sessionKey));
            System.out.println( " sessionKey.lengt :"+ sessionKey.length);

            byte [] privKeyEncript = scEnc.encryptCBC(privateKeyByte,passphraseByte);
            System.out.println( " privateKeyByte:  "+arrayByteToString(privateKeyByte));

            writeFile(filePrivateKeyCiphered,privKeyEncript);


        }catch(Exception e){
            System.out.println(" Exception  "+e.getMessage()+"   message  ") ;
            e.printStackTrace();
        }

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


    }

