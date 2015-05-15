/*
 * Copyright (C) 2013 The Android Open Source Project
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
package com.example.android.cardreader;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;

import com.example.android.common.logger.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import android.util.Base64;

import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.util.Scanner;

import edu.mit.anonauth.ProtocolDoor;

/**
 * Callback class, invoked when an NFC card is scanned while the device is running in reader mode.
 *
 * Reader mode can be invoked by calling NfcAdapter
 */
public class AccessCardReader implements NfcAdapter.ReaderCallback {
    private static final String TAG = "LoyaltyCardReader";
    // AID for our loyalty card service.
    private static final String ACCESS_CARD_AID = "F222222222";
    // ISO-DEP command HEADER for selecting an AID.
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String SELECT_APDU_HEADER = "00A40400";
    private static final String BROADCAST_APDU_HEADER = "00CA0000";
    // "OK" status word sent in response to SELECT AID command (0x9000)
    private static final byte[] SELECT_OK_SW = {(byte) 0x90, (byte) 0x00};

    private static Context context;
    //Hardcoded encoding of door information
    ProtocolDoor protocolDoor;
    private static final String DOOR_FILE = "doorInfo.txt";

    //Method to get a protocol door out of a string containing door information
    public ProtocolDoor getDoor(String str) {
        byte[] enc = Base64.decode(str, Base64.DEFAULT);
        ByteArrayInputStream bi = new ByteArrayInputStream(enc);
        ObjectInputStream si = null;
        ProtocolDoor protocolDoor = null;
        try {
            si = new ObjectInputStream(bi);
            protocolDoor = (ProtocolDoor) si.readObject();
        } catch (Exception e) {
            throw new RuntimeException("Deserialization error.");
        }
        return protocolDoor;
    }

     //Return hardcoded string representation of door information
    public String loadDoorInfo(String fileName) {
        InputStream doorStream;
        try {
            doorStream = context.getAssets().open(fileName);
        } catch (IOException e) {
            throw new RuntimeException("Door file not found.");
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(doorStream));
        StringBuilder out = new StringBuilder();
        String line = "";
        try {
            line = reader.readLine();
        } catch (IOException e) {
            throw new RuntimeException("Door file empty.");
        }
        try {
            reader.close();
        } catch (IOException e) {
            throw new RuntimeException("Reader failed to close.");
        }
        return line;
    }

    // Weak reference to prevent retain loop. mAccessCallback is responsible for exiting
    // foreground mode before it becomes invalid (e.g. during onPause() or onStop()).
    private WeakReference<AccessCallback> mAccessCallback;

    public interface AccessCallback {
        public void onResponseReceived(byte[] response);
    }

    public AccessCardReader(AccessCallback accessCallback, Context ctx) {
        mAccessCallback = new WeakReference<AccessCallback>(accessCallback);
        context = ctx;
        protocolDoor = getDoor(loadDoorInfo(DOOR_FILE));
    }

    /**
     * Callback when a new tag is discovered by the system.
     *
     * <p>Communication with the card should take place here.
     *
     * @param tag Discovered tag
     */
    @Override
    public void onTagDiscovered(Tag tag) {
        Log.i(TAG, "New tag discovered");
        // Android's Host-based Card Emulation (HCE) feature implements the ISO-DEP (ISO 14443-4)
        // protocol.
        //
        // In order to communicate with a device using HCE, the discovered tag should be processed
        // using the IsoDep class.
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
            try {
                // Connect to the remote NFC device
                isoDep.connect();
                // Build SELECT AID command for our loyalty card service.
                // This command tells the remote device which service we wish to communicate with.
                Log.i(TAG, "Requesting remote AID: " + ACCESS_CARD_AID);
                byte[] command = BuildSelectApdu(ACCESS_CARD_AID);
                // Send command to remote device
                Log.i(TAG, "Sending: " + ByteArrayToHexString(command));
                byte[] result = isoDep.transceive(command);
                // If AID is successfully selected, 0x9000 is returned as the status word (last 2
                // bytes of the result) by convention. Everything before the status word is
                // optional payload, which is used here to hold the account number.
                int resultLength = result.length;
                byte[] statusWord = {result[resultLength-2], result[resultLength-1]};
                byte[] payload = Arrays.copyOf(result, resultLength-2);
                if (Arrays.equals(SELECT_OK_SW, statusWord)) { //We're good to go for sending more commands
                    //Send command
                    command = BuildBroaddcastApdu(protocolDoor.getBroadcast());
                    Log.i(TAG, "Sending: " + ByteArrayToHexString(command));
                    result = isoDep.transceive(command); //Get response back from card
                    mAccessCallback.get().onResponseReceived(result); //Give response back to CardReaderFragment to verify HMAC
                }

            } catch (IOException e) {
                Log.e(TAG, "Error communicating with card: " + e.toString());
            }
        }
    }

    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildSelectApdu(String aid) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(SELECT_APDU_HEADER + String.format("%02X", aid.length() / 2) + aid);
    }

    public static byte[] BuildBroaddcastApdu(byte[] broadcast) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        byte[] header = HexStringToByteArray(BROADCAST_APDU_HEADER + String.format("%02X", broadcast.length));
        byte[] command = new byte[header.length + broadcast.length];

        System.arraycopy(header, 0, command, 0, header.length);
        System.arraycopy(broadcast, 0, command, header.length, broadcast.length);

        return command;
    }

    /**
     * Utility class to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for ( int j = 0; j < bytes.length; j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Utility class to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     */
    public static byte[] HexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
