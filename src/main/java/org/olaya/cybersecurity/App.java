package org.olaya.cybersecurity;

import sun.java2d.pipe.SpanShapeRenderer;

import java.io.*;
import java.util.Arrays;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Hello world!
 *
 */
public class App
{
    // MAIN PRACTICA 1
/**
    public static void main( String[] args ) throws Exception {

        SymmetricCipher  scEnc= new SymmetricCipher();
        System.out.println( "Hello World!" );
        // Fichero que contiene el texto String o texto plano a encriptar
        String file_path="/Users/olaya/IdeaProjects/practica1_dataprotection/text.txt";
        // Fichero que contiene el texto encriptado
        String ecoutput_path="/Users/olaya/IdeaProjects/practica1_dataprotection/ecoutput.txt";

        System.out.println("String plain text - input :  "+arrayByteToString(readFile(file_path)));
        //sc.readfile(file_path);

        byte[] encrypted_message= scEnc.encryptCBC(readFile(file_path), scEnc.iv);
        System.out.println("String text encripted :"+Arrays.toString(encrypted_message));

        writeFile(ecoutput_path,encrypted_message);

        SymmetricCipher  scDec= new SymmetricCipher();


        byte[] decrypted_message= scDec.decryptCBC(encrypted_message, scDec.iv);
        System.out.println("String text decripted : "+arrayByteToString(decrypted_message));

    }

*/
 //PRACTICA 2
/**
 public static void main( String[] args ) {

     System.out.println("Hello World!  Practica 2 ----");

     RSALibrary rsaLibrary = new RSALibrary();
     try {
         rsaLibrary.generateKeys();

     String filePath="/Users/olaya/IdeaProjects/practica1_dataprotection/text.txt";
     String filePublicKey="/Users/olaya/IdeaProjects/practica1_dataprotection/public.key";
     String filePrivateKey="/Users/olaya/IdeaProjects/practica1_dataprotection/private.key";
     // leo clave publica
         System.out.println("  String plain text - input :  "+arrayByteToString(readFile(filePath)));


         FileInputStream publicFile = new FileInputStream(filePublicKey);
         ObjectInputStream objetoPublicKey = new ObjectInputStream(publicFile);
         PublicKey publicKey = (PublicKey) objetoPublicKey.readObject();

     // Encriptamos
        byte [] RSAencript =rsaLibrary.encrypt(readFile(filePath),publicKey);
        System.out.println(" Clave publica encriptada formato byte "+Arrays.toString(RSAencript));

     // Leo clave privada

         FileInputStream privateFile = new FileInputStream(filePrivateKey);
         ObjectInputStream objetoPrivateKey = new ObjectInputStream(privateFile);
         PrivateKey privateKey = (PrivateKey) objetoPrivateKey.readObject();
        // System.out.println(" Clave privada formato byte"+Arrays.toString(pub));

     // desecriptamos

        byte[] decrypted_message= rsaLibrary.decrypt(RSAencript,privateKey);
        System.out.println("  string text decripted to String : "+decrypted_message.toString());
        System.out.println("  string text decripted  "+arrayByteToString(decrypted_message));

     // Firmamos
         byte[] signature= rsaLibrary.sign(readFile(filePath),privateKey);
         System.out.println("Mensaje con Firma :  "+arrayByteToString(signature));


     // Verificamos Firma
         boolean is_OK= rsaLibrary.verify(readFile(filePath),signature,publicKey);
         System.out.println("Firma correcta ?? :  "+is_OK);
     // Prueba, meto private2.key clave antigua para ver que falla.
         String filePublicKey2="/Users/olaya/IdeaProjects/practica1_dataprotection/private2.key";

         FileInputStream privateFile2 = new FileInputStream(filePublicKey2);
         ObjectInputStream objetoPrivateKey2 = new ObjectInputStream(privateFile2);
         PrivateKey privateKey2 = (PrivateKey) objetoPrivateKey2.readObject();

         byte[] signature2= rsaLibrary.sign(readFile(filePath),privateKey2);
         System.out.println("Prueba 1 : Mensaje con Firma2 (la clave no se corresponde con la clave publica correcta) : ");
         System.out.println(arrayByteToString(signature2));
         // Verificamos Firma2. provocamos un fallo
         boolean is_OK2= rsaLibrary.verify(readFile(filePath),signature2,publicKey);
         System.out.println("Firma2 correcta ?? :  "+is_OK2);

      // Prueba, si modifico el mensaje plaintext
         String new_text= "Esto es un texto para cambiar las cosas.";
         System.out.println("Prueba 2 : Cambio el texto de entrada .Texto new_text :"+new_text.toString());
         System.out.println("Texto new_text en bytes :"+new_text.getBytes().length);

         boolean is_OK3= rsaLibrary.verify(new_text.getBytes(),signature,publicKey);
         System.out.println("Firma3 correcta ?? :  "+is_OK3);



     }catch(Exception e){e.printStackTrace();}


 }
*/


 public static void main( String[] args ) throws Exception {
     // capturar la excepción y manejar que no se quede vacia ni sean mas de 16bytes.

 System.out.println("Hello World!  Practica 3 ----");

    System.out.println("args "+Arrays.toString(args));

     SimpleSec simpleSec = new SimpleSec();
     System.out.println("Main - Generamos Claves : ----------------------------------------------- ");
     simpleSec.call("g","text.txt","SALIDA.txt");
     System.out.println("------------------------------------------------------------------------- ");
     System.out.println("Main - Encriptamos fichero: --------------------------------------------- ");
     simpleSec.call("e","text.txt","ficheroSALIDA.txt");
     System.out.println("------------------------------------------------------------------------- ");
     System.out.println("Main - DESencriptamos fichero: ------------------------------------------ ");
     simpleSec.call("d","ficheroSALIDA.txt","textDECRIPTED.txt");


 }



    /*************************************************************************************/
    /* Method arrayByteToString para convertir a char un array */
    /*************************************************************************************/
    public static String arrayByteToString(byte[] array ){

        String out="";
        for (byte b :array){
            out=out + (char)b;
        }
        return out;
    }

    /*************************************************************************************/
    /* Method readfile */
    /*************************************************************************************/
    public static byte[] readFile (String file_path) throws Exception {
        FileInputStream file_stream=null;
        File file_text= new File(file_path);
        byte [] text_bytes=new byte [(int)file_text.length()];
        try {
            //text_bytes = new byte[(int) file_text.length()];
            file_stream=new FileInputStream(file_text);
            file_stream.read(text_bytes);
        }
        catch(IOException e) { e.printStackTrace();}
        finally { if(file_stream != null) {
            try{
                file_stream.close();
            }catch (IOException e){e.printStackTrace();}
        }
        }
        return text_bytes;
    }

    /*************************************************************************************/
    /* Method writefile */
    /*************************************************************************************/
    public static void writeFile (String output_path, byte [] output) throws Exception {
        Writer writer = null;

        try {
            writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(output_path), "US-ASCII"));
            writer.write(arrayByteToString(output));
        } catch (IOException ex) {} finally {
            try {writer.close();} catch (Exception ex) {}
        }
    }


}
