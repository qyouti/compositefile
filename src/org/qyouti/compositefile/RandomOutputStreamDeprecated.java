package org.qyouti.compositefile;


import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author maber01
 */
public class RandomOutputStreamDeprecated extends OutputStream
{

    RandomAccessFile rafile;

    public RandomOutputStreamDeprecated(RandomAccessFile rafile)
    {
        this.rafile = rafile;
    }

    @Override
    public void write(int b) throws IOException
    {
        rafile.write(b);
    }

    @Override
    public void close() throws IOException
    {
        rafile.close();
    }

    @Override
    public void flush() throws IOException
    {
        // nop
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException
    {
        rafile.write(b, off, len);
    }

    @Override
    public void write(byte[] b) throws IOException
    {
        rafile.write(b);
    }

}
