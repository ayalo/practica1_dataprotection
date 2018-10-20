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



public class SimpleSec {

    RSALibrary rsaLibrary = new RSALibrary();      // Practica 2
    SymmetricCipher scEnc= new SymmetricCipher();  // Practica 1
    KeyPair pair =null;
    String filePath =null;
    String claveprivada = "./private_original.key"; //BORRAR
    String pathSalida = "./privateKeyDECRIPTED.key"; //BORRAR
    String pathSalidaBACK = "./privateKeyDECRIPTEDBACK.key"; //BORRAR
    String destinationFile="";
    String fileENCRIPTED=""; // para el decript y no sobreescribir
    String destinationFileDECRIPTED=""; // para el decript y no sobreescribir


    public void  call (String command, String sourceFile, String destinationFile )throws Exception {

        if (command == "g") {
            filePath=sourceFile;
            pair=getPairKeys();

        } else if (command == "e") {
            //filePath="./"+sourceFile;
            //destinationFile="./"+destinationFile;
            filePath=sourceFile;
            destinationFile=destinationFile;
            //if [pair == null ]  --> tratar
            getENCText(filePath, destinationFile,pair);

        } else if (command == "d") {
            fileENCRIPTED=sourceFile;
            destinationFileDECRIPTED=destinationFile;
            //System.out.println("fileENCRIP.length = "+fileENCRIPTED.length());
            //System.out.println("destinationFileDECRIPTED.length = "+destinationFileDECRIPTED.length());

            //if [pair == null ]  --> tratar
            getDECText(fileENCRIPTED,destinationFileDECRIPTED,pair);

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

        //String filePath = sourceFile;
        // Establish random sessionKey
        SecureRandom r = new SecureRandom();
        byte[] sessionKey = new byte[16];
        r.nextBytes(sessionKey);
        System.out.println("getENCText - SessionKey al inicio : "+sessionKey.length);
        System.out.println("getENCText - SessionKey byts:"+arrayByteToString(sessionKey));

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

/**        System.out.println("SimpleSec - fichero a guardar en disco :");
        // filePath =giveMeTextFile();
        System.out.println("String plain text - input :  "+arrayByteToString(readFile(filePath)));
*/
        // Cipher plaintext input encripted with SessionKey
        byte[] encryptedPlainText = scEnc.encryptCBC(readFile(filePath), sessionKey);
        //System.out.println("SimpleSec - String plaintext encripted with sessionKey length: "+encryptedPlainText.length);
        //System.out.println("SimpleSec - publicKey length: " + publicKey.toString());

        // SesionKey encripted with publicKey
        byte[] sessionKeyEncripted= rsaLibrary.encrypt(sessionKey, publicKey);
        //System.out.println("SimpleSec - SessionKey encripted with publicKey length: " + sessionKeyEncripted.length);

        // PrivateKey Desencript
/**  Meter en funcion */
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

 /**       PrivateKey privateKeyDEC = getPrivateKeyDECRIPTED("privateKeyDECRIPTED.key"); */

        //System.out.println("Calculamos Firma---  ");
        // Signature encryptedPlainText ( firma del texto encriptado)
        //byte [] finalEncriptedFile =new byte[encryptedPlainText.length + sessionKeyEncripted.length+];
         //   System.arraycopy(encryptedPlainText, 0, finalEncriptedFile, 0, encryptedPlainText.length);
         //   System.arraycopy(sessionKeyEncripted, 0, finalEncriptedFile, encryptedPlainText.length, sessionKeyEncripted.length);


            //byte [] fileSigned= rsaLibrary.sign(finalEncriptedFile,privateKeyDEC);
        //System.out.println("Longitud Firma :  "+fileSigned.length);

        //Concatenation encryptedPlainText and sessionKeyEncripted + (falta ) la firma
        byte [] finalEncriptedFile =new byte[encryptedPlainText.length + sessionKeyEncripted.length]; // por ser RSA 1024 la firma ocupa eso
        System.arraycopy(encryptedPlainText, 0, finalEncriptedFile, 0, encryptedPlainText.length);
        System.arraycopy(sessionKeyEncripted, 0, finalEncriptedFile, encryptedPlainText.length, sessionKeyEncripted.length);
        byte [] signature= rsaLibrary.sign(finalEncriptedFile,privateKeyDEC);
        byte [] fileSigned=new byte [finalEncriptedFile.length+signature.length];
        System.arraycopy(finalEncriptedFile, 0, fileSigned, 0, finalEncriptedFile.length);
        System.arraycopy(signature, 0, fileSigned, finalEncriptedFile.length, signature.length);

        //byte [] finalEncriptedFile = Arrays.copyOfRange(fileSigned,0,fileSigned.length );
        //System.out.println("SimpleSec -  finalEncriptedFile.length : " +finalEncriptedFile.length);

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
        //System.out.println("SimpleSec - privateKeyByte.length = "+privateKeyByte.length);
        //System.out.println( "SimpleSec -  privateKeyByte.length CON PAD :  "+privKeyEncript.length);
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
        //System.out.println( "SimpleSec -  privKeyDECRIPTED.length :  "+privKeyDEncript.length);
        //System.out.println( "SimpleSec -  privKeyDECRIPTED.toString :  "+arrayByteToString(privKeyDEncript));
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
    // devuelte texto session y firma byte [][]
    public byte [][]  extract (String fileENCRIPTED) {

        byte[][] extracted = new byte[3][];
        byte [] sourceBytes=null;
        Path fileENCRIPTEDPath= Paths.get(fileENCRIPTED);
        try {
            sourceBytes = Files.readAllBytes(fileENCRIPTEDPath);
        }catch (Exception e) { e.printStackTrace();}

        System.out.println("extract -  publicKey.lenght : " + pair.getPublic().getEncoded().length);
        System.out.println("extract -  sourceBytes of fileENCRIPTED.lenght : " + sourceBytes.length);

        System.out.println("extract -  Indice que se va ahora  desde 0 hasta : " + (sourceBytes.length-128-128));

        byte [] encryptedPlainText = Arrays.copyOfRange(sourceBytes,0, sourceBytes.length-128-128); //Suponemos firma y ENCsessionKey+publicKey.length =128each
        System.out.println("extract -  Extracting encryptedPlainText .lenght : " + encryptedPlainText.length);
        System.out.println("extract -  Extracting encryptedPlainText.length : " +(encryptedPlainText.length)+" hasta "+(encryptedPlainText.length+127));

        System.out.println("extract -  Extracting sourceBytes.length-128 : " +(sourceBytes.length-128)+" hasta "+sourceBytes.length );
        byte [] signature = Arrays.copyOfRange(sourceBytes, sourceBytes.length-128, sourceBytes.length);
        System.out.println("extract -  Extracting signature .lenght : " + signature.length);

        byte [] sessionKeyEncripted= Arrays.copyOfRange(sourceBytes,encryptedPlainText.length, encryptedPlainText.length+127);
        System.out.println("extract -  Extracting sessionKeyEncripted .lenght : " + sessionKeyEncripted.length);

        // byte [] sesssion_key = pair.getPublic().getEncoded().length;
        extracted [0]= encryptedPlainText;
        extracted [1]= sessionKeyEncripted;
        extracted [2]= signature;

        return extracted;
    }

    public PrivateKey getPrivateKeyDECRIPTED (String path) {
        String pathSalida = path;
        PrivateKey privateKeyDEC=null;
        try{
            System.out.println("getPrivateKeyDECRIPTED - Desencriptamos la privateKey  : ");

            byte[] privKeyDEncript = decriptPrivateKey(rsaLibrary.PRIVATE_KEY_FILE, giveMePassphrase(), pathSalida);
            //System.out.println("SimpleSec - Que vale salidaDECPrivKey : " + arrayByteToString(privKeyDEncript));

            KeyFactory keyFactory = KeyFactory.getInstance(rsaLibrary.ALGORITHM);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyDEncript);
            privateKeyDEC = keyFactory.generatePrivate(privateKeySpec);

            // Luego la escribo en un fichero por si acaso
            FileOutputStream privateFileAfterDEC = new FileOutputStream(pathSalida);
            privateFileAfterDEC.write(privKeyDEncript);
        }catch(Exception e){ e.printStackTrace();}

        return privateKeyDEC;

    }

    public void getDECText( String fileENCRIPTED,String destinationFileDECRIPTED,KeyPair pair){
        //byte [][] extracted = extract(fileENCRIPTED);
        //System.out.println("getDECText-  extracted.length = "+extracted.length);

        byte [] sourceBytes=null;
        Path fileENCRIPTEDPath= Paths.get(fileENCRIPTED);
        try {
            sourceBytes = Files.readAllBytes(fileENCRIPTEDPath);
        }catch (Exception e) { e.printStackTrace();}

        System.out.println("extract -  publicKey.lenght : " + pair.getPublic().getEncoded().length);
        System.out.println("extract -  sourceBytes of fileENCRIPTED.lenght : " + sourceBytes.length);

        System.out.println("extract -  Indice que se va ahora  desde 0 hasta : " + (sourceBytes.length-128-128));

        /**byte [] encryptedPlainText= Arrays.copyOfRange(sourceBytes,0, sourceBytes.length-128-128); //Suponemos firma y ENCsessionKey+publicKey.length =128each
        System.out.println("extract -  Extracting encryptedPlainText .lenght : " + encryptedPlainText.length);
        System.out.println("extract -  Extracting encryptedPlainText.length : " +(encryptedPlainText.length)+" hasta "+(encryptedPlainText.length+127));
*/
        System.out.println("extract -  Extracting sourceBytes.length-128 : " +(sourceBytes.length-128)+" hasta "+sourceBytes.length );
        byte [] signature = Arrays.copyOfRange(sourceBytes, sourceBytes.length-128, sourceBytes.length);
        System.out.println("extract -  Extracting signature .lenght : " + signature.length);
/**
        byte [] sessionKeyEncripted= Arrays.copyOfRange(sourceBytes,encryptedPlainText.length, encryptedPlainText.length+127);
        System.out.println("extract -  Extracting sessionKeyEncripted .lenght : " + sessionKeyEncripted.length);
*/
        byte [] fileSigned = Arrays.copyOfRange(sourceBytes,0, sourceBytes.length-128);


        System.out.println("getDECText-  Verificamos firma : ");
        //    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {
        // Verificamos Firma

         boolean is_OK= rsaLibrary.verify(fileSigned,signature,pair.getPublic());
         System.out.println("Firma correcta ?? :  "+is_OK);


        // Obtenemos PrivateKey necesaria para obtener todo lo demas
      //  System.out.println("getDECText-  Saco de nuevo privateKey");
         //PrivateKey privateKey = getPrivateKeyDECRIPTED();
   /**     PrivateKey privateKeyDEC=null;
        try {
*/
            /**  Meter en funcion */
   /**         System.out.println("getDECText - Desencriptamos la privateKey para ver si queda igual : ");
            String pathSalida = "./privateKeyDECRIPTED3.key";
            byte[] privKeyDEncript = decriptPrivateKey(rsaLibrary.PRIVATE_KEY_FILE, giveMePassphrase(), pathSalida);
            System.out.println("getDECText - Que vale salidaDECPrivKey : " + arrayByteToString(privKeyDEncript));

            KeyFactory keyFactory = KeyFactory.getInstance(rsaLibrary.ALGORITHM);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyDEncript);
            privateKeyDEC = keyFactory.generatePrivate(privateKeySpec);

            // Luego la escribo en un fichero por si acaso
            FileOutputStream privateFileAfterDEC = new FileOutputStream(pathSalida);
            privateFileAfterDEC.write(privKeyDEncript);
            /** hasta aqui meter en funcion*/

            //}catch(Exception e){e.printStackTrace();}


        //Decrypting the SessionKey DES Pract2
        //        public byte[] decrypt(byte[] ciphertext, PrivateKey key) {
  /**      System.out.println("getDECText - encript [2] para sacar SessionKey= "+arrayByteToString(extracted[2]));
        byte [] sessionKey = rsaLibrary.decrypt(extracted[2],privateKeyDEC);

        System.out.println(" desecnriptada sessionKey : " +sessionKey.length);
        System.out.println(" desecnriptada sessionKey bytes : " +arrayByteToString(sessionKey));
*/




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

