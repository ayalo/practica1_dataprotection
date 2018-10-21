package org.olaya.cybersecurity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Hello world!
 *
 */
public class App
{
/** PRACTICA 3*/

 public static void main( String[] args ) throws Exception {
     // capturar la excepción y manejar que no se quede vacia ni sean mas de 16bytes.

  System.out.println("Hello World!  Practica 3 ----");

    System.out.println("args "+Arrays.toString(args));
  //   System.out.println("args [0]"+args[0]);


     String mode=null;
     String sourceFile=null;
     String destinationFile=null;

     if (args.length ==3 || (args.length==1 && args[0].equals("g"))) {
         try {
             mode = (String) args[0];
             if (!args[0].equals("g")) {
                 sourceFile = (String) args[1];
                 destinationFile = (String) args[2];
             }
         } catch (Exception e) {
             System.err.println("Arguments must be an String.");
             System.exit(1);
         }
     }else  {
         System.err.println("You must enter the correct arguments  ");
         System.exit(1);
     }


     System.out.println("mode = "+mode);
     System.out.println("sourceFile = "+sourceFile);
     System.out.println("destinationFile = "+destinationFile);

     SimpleSec simpleSec = new SimpleSec();
     if (mode.equals("g") || mode.equals("e") || mode.equals("d")) {
         System.out.println("Main -------------------------------------------------------------------- ");
         simpleSec.call(mode, sourceFile, destinationFile);
         System.out.println("------------------------------------------------------------------------- ");
     }else {
         System.err.println("Arguments are invalid. ");
         System.out.println("You must enter the correct arguments : ");
         System.out.println ("To execute the jar file like this example: ");
         System.out.println ("To Generate KeyPair:   ");
         System.out.println("java -cp target/practica3_dataprotection-1.0-SNAPSHOT.jar org.olaya.cybersecurity.App g ");
         System.out.println ("   ");
         System.out.println ("To Encrypt:    ");
         System.out.println("java -cp target/practica3_dataprotection-1.0-SNAPSHOT.jar org.olaya.cybersecurity.App e textSourceToEncrypt.txt outputFileEncrypted.txt");
         System.out.println ("   ");
         System.out.println ("To Decrypt:   ");
         System.out.println("java -cp target/practica3_dataprotection-1.0-SNAPSHOT.jar org.olaya.cybersecurity.App d FileEncrypted.txt outputTextDecrypted.txt");
         System.out.println ("   ");
         System.out.println(" Write  arguments: mode sourceFile destinationFile");
         System.out.println(" mode could be : ");
         System.out.println("                  g : generate Pair of Keys.");
         System.out.println("                  e : encript sourceFile.");
         System.out.println("                  d : decript sourceFile");

         System.exit(1);
     }





}
/*

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
 */

}
