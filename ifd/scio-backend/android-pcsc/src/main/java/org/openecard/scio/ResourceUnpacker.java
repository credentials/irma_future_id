/****************************************************************************
 * Copyright (C) 2012 HS Coburg.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file is part of the Open eCard App.
 *
 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 * Other Usage
 * Alternatively, this file may be used in accordance with the terms
 * and conditions contained in a signed written agreement between
 * you and ecsec GmbH.
 *
 ***************************************************************************/

package org.openecard.scio;

import android.content.Context;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.openecard.android.pcsc.R;


/**
 * This class is used to unpack zipped resources (e.g. pcsc drivers) to make them accessible for the app.
 *
 * @author Dirk Petrautzki <petrautzki@hs-coburg.de>
 *
 */
public class ResourceUnpacker {

    /**
     * Unpacks a zipped resource to a specific folder.
     *
     * @param ctx the application context
     */
    public static void unpackResources(Context ctx) {

	InputStream ins = ctx.getResources().openRawResource(R.raw.drivers);

	if (ins != null) {
	    File f = new File(ctx.getFilesDir() + "/drivers");
	    if (f.exists()) {
		deleteDir(f);
	    }
	    try {
		ResourceUnpacker.unpackResources(ins, ctx.getFilesDir());
	    } catch (FileNotFoundException e) {
		// TODO LOG
		throw new RuntimeException("Cannot get drivers resource.", e);
	    } catch (IOException e) {
		// TODO LOG
		throw new RuntimeException("Cannot get drivers resource.", e);
	    }
	} else {
	    throw new RuntimeException("Cannot get drivers resource.");
	}
    }

    /**
     * @param ins An inputstream pointing to the resource to unpack
     * @param file Destination folder where the resource is unpacked to
     * @throws IOException If an io related error occurs while unpacking the resource
     */
    private static void unpackResources(InputStream ins, File file) throws IOException {
	// Open the ZipInputStream
	ZipInputStream inputStream = new ZipInputStream(ins);

	// Loop through all the files and folders
	for (ZipEntry entry = inputStream.getNextEntry(); entry != null; entry = inputStream.getNextEntry()) {
	    String innerFileName = file + File.separator + entry.getName();
	    File innerFile = new File(innerFileName);
	    if (innerFile.exists()) {
		innerFile.delete();
	    }

	    // Check if it is a folder
	    if (entry.isDirectory()) {
		// Its a folder, create that folder
		innerFile.mkdirs();
	    } else {
		// Create a file output stream
		FileOutputStream outputStream = new FileOutputStream(innerFileName);
		final int BUFFER = 2048;

		// Buffer the ouput to the file
		BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream, BUFFER);

		// Write the contents
		int count;
		byte[] data = new byte[BUFFER];
		while ((count = inputStream.read(data, 0, BUFFER)) != -1) {
		    bufferedOutputStream.write(data, 0, count);
		}

		// Flush and close the buffers
		bufferedOutputStream.flush();
		bufferedOutputStream.close();
	    }

	    // Close the current entry
	    inputStream.closeEntry();
	}
	inputStream.close();
    }

    /**
     * Delete a directory and all contained files and subdirectories.
     *
     * @param dir
     *            the directory to delete
     * @return true if successfully deleted, else false
     */
    private static boolean deleteDir(File dir) {
	// recursively remove all files and subdirectories
	if (dir.isDirectory()) {
	    String[] children = dir.list();
	    for (int i = 0; i < children.length; i++) {
		boolean success = deleteDir(new File(dir, children[i]));
		if (!success) {
		    return false;
		}
	    }
	}

	// The directory is now empty so delete it
	return dir.delete();
    }

}
