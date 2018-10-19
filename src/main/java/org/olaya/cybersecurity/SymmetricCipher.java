
package org.olaya.cybersecurity;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.Cipher;
import java.nio.*;

public class SymmetricCipher {

    byte[] byteKey;
    SymmetricEncryption s;
    SymmetricEncryption d;

    // Initialization Vector (fixed)

    byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
            (byte)53, (byte)54};

    //Mis variables
    int block_size= 16; // fijo el tamaño de bloque

    /*************************************************************************************/
    /* Constructor method */
    /*************************************************************************************/
    public void SymmetricCipher() {

    }

    /*************************************************************************************/
    /* Method to encrypt using AES/CBC/PKCS5 */
    /* @ xor */
    /* @ addPading */
    /* @ encriptBlock */
    /*************************************************************************************/
    public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
        int len_pad= block_size -(input.length % block_size); //5 char  .
        int len_withpad = input.length + block_size - (input.length % block_size);// ej. 32 char mete bloque de mas si se ajusta al tamaño

        //System.out.println("SymmetricCipher - Estoy en encryptCBC");
        ///System.out.println(" encryptCBC, len_withpad "+len_withpad);
        ///System.out.println(" encryptCBC, len_pad "+len_pad);

        // Generate the plaintext with padding
        byte [][] ec= addPadding(input);  // tendriamos que contemplar si la salida no tiene el texto padeado o se ha perdido algun byte
        byte[] ciphertext = new byte [ec.length*block_size];

        byte [][] cipher2d= new byte[ec.length][block_size];; // array con los bloques encriptados + padding //quiza sobre uno
         // idem que ciper2d pero 1d

        // Generate the ciphertext
        try {
            s = new SymmetricEncryption(byteKey);
            cipher2d[0] = s.encryptBlock(xor(ec[0], iv));

            for (int i = 1; i < ec.length; i++) {
                cipher2d[i] = s.encryptBlock(xor(ec[i], cipher2d[i - 1]));
            }
            int ini = 0;
            for (byte[] bloque : cipher2d) {
                System.arraycopy(bloque, 0, ciphertext, ini, block_size);
                ini += block_size;
            }
        }catch(Exception e){e.getMessage();}
        //System.out.println("SymmetricCipher - Encript, imprimo array 2d cipher2d :");
        //System.out.println(Arrays.deepToString(cipher2d));

        return ciphertext;
    }


    /*************************************************************************************/
    /* Method to decrypt using AES/CBC/PKCS5 */
    /* @ iniEC */
    /* @ xor */
    /* @ decriptBlock */
    /* @ unPadding */
    /*************************************************************************************/


    public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

        System.out.println("SymmetricCipher - Estoy en decryptCBC");
        int len_pad=0;
        int len_withpad=input.length;
        int total_blocks= len_withpad / block_size;

        d = new SymmetricEncryption(byteKey);

        //System.out.println(" decryptCBC, len_withpad "+len_withpad);
        //System.out.println(" decryptCBC, len_pad "+len_pad);
        //System.out.println(" decryptCBC, total_blocks "+total_blocks);
        byte [][] ec= iniEc(input,input.length/block_size,len_withpad);

        byte[] finalplaintext = new byte [ec.length*block_size];

        byte [][] cipher2d= new byte[ec.length][block_size];;
        // idem que ciper2d pero 1d

        try{
            cipher2d[0] = xor(d.decryptBlock(ec[0]), iv);

        for (int i = 1; i < ec.length; i++) {
            cipher2d[i] = xor(d.decryptBlock(ec[i]), ec[i - 1]);
        }
        }catch(Exception e){e.printStackTrace();}

        try {
            int last = (int) cipher2d[total_blocks-1][block_size-1];
                for (int i =(int)cipher2d[total_blocks-1].length - last; i < block_size; i++) {
                    if ((int) cipher2d[total_blocks-1][i] != last) {
                        System.out.println("SymmetricCipher - Error en el padding. No se puede recuperar el mensaje.");
                        throw  new BadPaddingException();
                    } else len_pad = last;
                }
        }catch (ArrayIndexOutOfBoundsException e ){
            System.out.println("SymmetricCipher - Exception  "+e.getMessage()+"   message  ") ; // java.lang.ArrayIndexOutOfBoundsException:
            e.printStackTrace();
        }

        // Quitamos Padding
        cipher2d = unPadding(cipher2d, len_pad);

        int ini = 0;
        for (byte[] bloque : cipher2d) {
            System.arraycopy(bloque, 0, finalplaintext, ini, block_size);
            ini += block_size;
        }
        // }catch (BadPaddingException e){e.getMessage();}
        // devuelvo el plaintext sin los bytes de padding de 0's
        byte [] salida= Arrays.copyOfRange(finalplaintext,0,finalplaintext.length-len_pad);
        //System.out.println("SymmetricCipher - Array sin pad antes de retur decript:" +Arrays.toString(salida));

        return salida;  //Arrays.copyOfRange(finalplaintext,0,finalplaintext.length-len_pad);
    }

    /*************************************************************************************/
    /* Method iniEc */
    /*************************************************************************************/
    public byte [][] iniEc(byte [] ciphered,int len_pad,int len_withpad) throws Exception{
        int total_blocks= len_withpad / block_size;
        byte[][] ec = new byte[total_blocks][block_size];
        try{
            int ini = 0;
            for (int i = 0; i < (ec.length); i++) {
                ec[i] = Arrays.copyOfRange(ciphered, ini, ini + block_size);
                ini += block_size;
            }
        }catch (Exception e){e.printStackTrace();}
        return ec;
    }

    /*************************************************************************************/
    /* Method addPadding */
    /*************************************************************************************/
    /** @exception IllegalBlockSizeException if the cipher is a block cipher, no padding has
    been requested, and the length of the encoding of the key to be wrapped is not a
    multiple of the block size. If the ciphertext is too large.

    @exception BadPaddingException If the ciphertext is invalid.
    */
    public byte[][] addPadding (byte[] input) throws Exception {

        int len_withpad = input.length + block_size - (input.length % block_size);
        int len_pad= block_size -(input.length % block_size);

        //System.out.println(" addPadding, len_withpad "+len_withpad);
        //System.out.println(" addPadding, len_pad "+len_pad);

        int total_blocks=len_withpad/block_size;
            byte[][] ec =iniEc(input,len_pad,len_withpad);
        try{
             for (int i = (block_size - len_pad); i < block_size; i++) {
                 ec[total_blocks - 1][i] = (byte) len_pad;
                 //    throw new BadPaddingException;
             }
         }catch (Exception e){e.printStackTrace();} ////ArrayIndexOutOfBoundsException
        //System.out.println("SymmetricCipher - addPadding, imprimo array 2d ec de dimensiones " + ec.length + " :");
        //System.out.println(Arrays.deepToString(ec));

        return ec;
    }
    /*************************************************************************************/
    /* Method unPadding */
    /*************************************************************************************/
    public byte[][] unPadding (byte[][] cipheredPadded, int len_pad) throws Exception {
        int total_blocks=cipheredPadded.length;

        //System.out.println("SymmetricCipher - En unPadding cipheredPadded :"+total_blocks);
        //System.out.println(Arrays.deepToString(cipheredPadded));

        for (int i =(block_size-len_pad); i < block_size; i++) {
            cipheredPadded[total_blocks - 1][i] = (byte) 0x00;
        }

        //System.out.println("SymmetricCipher - Quitando el padding,  Contenido :");
        //System.out.println(Arrays.deepToString(cipheredPadded));

        return cipheredPadded;

    }


    /*************************************************************************************/
    /* Method XOR */
    /*************************************************************************************/
    public byte[] xor (byte[] bloque1, byte[] bloque2)  {

        byte [] resul= new byte [bloque1.length]; //bloque1.length siempre va a ser 16 pero por si acaso
        int i =0;
        for (byte b : bloque1){
            resul[i]=(byte)(b ^ bloque2[i++]);
        }
        return resul;
    }




}

