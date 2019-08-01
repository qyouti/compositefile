/*
 * Copyright 2019 Leeds Beckett University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.qyouti.compositefile;


import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;


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
