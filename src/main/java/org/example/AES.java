package org.example;

import java.util.Arrays;

public class AES {
    // Stałe z AES:
    private final int Nb = 4;               // liczba kolumn w stanie (zawsze 4 w AES)
    private final int Nk;                   // liczba słów w kluczu (4, 6 lub 8)
    private final int Nr;                   // liczba rund (10, 12, 14 zależnie od klucza)
    private final byte[][] roundKeys;       // tablica kluczy rundowych (rozszerzony klucz)

    public AES(byte[] key) {
        int keyBits = key.length * 8;
        if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
            throw new IllegalArgumentException("Obsługiwane długości klucza to 128, 192 lub 256 bitów.");
        }
        this.Nk = key.length / 4;
        this.Nr = Nk + 6;
        this.roundKeys = keyExpansion(key); // rozszerzenie klucza na wszystkie rundy
    }

    // Sprawdza i konwertuje klucz z formatu hex (jako String)
    public static byte[] parseKey(String hexKey) {
        if (!hexKey.matches("[0-9a-fA-F]+") || (hexKey.length() != 32 && hexKey.length() != 48 && hexKey.length() != 64)) {
            throw new IllegalArgumentException("Klucz musi być w formacie hex i mieć długość 32 (128-bit), 48 (192-bit) lub 64 (256-bit) znaków.");
        }
        return hexToBytes(hexKey);
    }

    // Zamienia String hex → tablicę bajtów
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Nieprawidłowa długość ciągu hex.");
        }
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }

    // Zamienia bajty na hex-string (np. do wyświetlenia)
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Tablica podstawień (S-Box)
    private static final int[] SBOX = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
            0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
            0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
            0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
            0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
            0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
            0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
            0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
            0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
            0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
            0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
            0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
            0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
            0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
            0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
            0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
            0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
            0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
            0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
            0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

    // Odwrotność S-Boxa (do deszyfrowania)
    private static final int[] INV_SBOX = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
            0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
            0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
            0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
            0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
            0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
            0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
            0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
            0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
            0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
            0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
            0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
            0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
            0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
            0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
            0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
            0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
            0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
            0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
            0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
            0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

    // Wektor RCON do rozszerzania klucza (pierwiastki w GF(2^8))
    private static final int[] RCON = {
            0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80,
            0x1B, 0x36, 0x6C, 0xD8,
            0xAB, 0x4D, 0x9A, 0x2F,
            0x5E, 0xBC, 0x63, 0xC6,
            0x97, 0x35, 0x6A, 0xD4,
            0xB3, 0x7D, 0xFA, 0xEF,
            0xC5, 0x91
    };

    // Szyfrowanie jednego bloku (16 bajtów)
    public byte[] encrypt(byte[] input) {
        byte[][] state = toState(input);
        addRoundKey(state, 0);        // pierwszy klucz rundowy

        for (int round = 1; round < Nr; round++) {
            subBytes(state);                // podstawienie przez S-Box
            shiftRows(state);               // podstawienie przez S-Box
            mixColumns(state);              // mieszanie kolumn
            addRoundKey(state, round);      // dodanie klucza rundowego
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Nr);             // ostatnia runda – bez mixColumns

        return fromState(state);
    }

    // Deszyfrowanie jednego bloku
    public byte[] decrypt(byte[] input) {
        byte[][] state = toState(input);
        addRoundKey(state, Nr);             // klucz ostatniej rundy

        for (int round = Nr - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        return fromState(state);
    }

    // Szyfrowanie wielu bloków
    public byte[] encryptMany(byte[] data) {
        byte[] padded = pad(data);
        byte[] output = new byte[padded.length];
        for (int i = 0; i < padded.length; i += 16) {
            byte[] block = Arrays.copyOfRange(padded, i, i + 16);
            byte[] encrypted = encrypt(block);
            System.arraycopy(encrypted, 0, output, i, 16);
        }
        return output;
    }

    // Deszyfrowanie wielu bloków
    public byte[] decryptMany(byte[] data) {
        byte[] output = new byte[data.length];
        for (int i = 0; i < data.length; i += 16) {
            byte[] block = Arrays.copyOfRange(data, i, i + 16);
            byte[] decrypted = decrypt(block);
            System.arraycopy(decrypted, 0, output, i, 16);
        }
        return unpad(output);
    }

    // Zero-padding: dodaje 0x00 na końcu
    private byte[] pad(byte[] data) {
        int paddingLength = (16 - (data.length % 16)) % 16;
        return Arrays.copyOf(data, data.length + paddingLength);
    }

    // Usuwanie 0x00 z końca (tylko dla zero-paddingu)
    private byte[] unpad(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i + 1);
    }

    // Rozszerzenie klucza (Key Expansion)
    private byte[][] keyExpansion(byte[] key) {
        byte[][] w = new byte[Nb * (Nr + 1)][4];
        for (int i = 0; i < Nk; i++) {
            w[i][0] = key[4 * i];
            w[i][1] = key[4 * i + 1];
            w[i][2] = key[4 * i + 2];
            w[i][3] = key[4 * i + 3];
        }
        byte[] temp;
        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            temp = Arrays.copyOf(w[i - 1], 4);
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp));
                temp[0] ^= (byte) RCON[(i / Nk) - 1];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            for (int j = 0; j < 4; j++)
                w[i][j] = (byte) (w[i - Nk][j] ^ temp[j]);
        }
        return w;
    }

    // Cykliczne przesunięcie słowa w lewo o 1 bajt
    private byte[] rotWord(byte[] word) {
        return new byte[]{word[1], word[2], word[3], word[0]};
    }

    // Podstawienie każdego bajtu przez SBOX
    private byte[] subWord(byte[] word) {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++)
            result[i] = (byte) SBOX[word[i] & 0xFF];
        return result;
    }

    // Zamiana tablicy 16 bajtów na macierz stanu 4x4 (kolumnowo)
    private byte[][] toState(byte[] input) {
        byte[][] state = new byte[4][Nb];
        for (int i = 0; i < input.length; i++)
            state[i % 4][i / 4] = input[i];
        return state;
    }

    // Zamiana stanu 4x4 na tablicę bajtów
    private byte[] fromState(byte[][] state) {
        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++)
            output[i] = state[i % 4][i / 4];
        return output;
    }

    // Dodanie klucza rundowego (XOR)
    private void addRoundKey(byte[][] state, int round) {
        for (int col = 0; col < Nb; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] ^= roundKeys[round * Nb + col][row];
            }
        }
    }

    // SubBytes – SBOX na każdym bajcie stanu
    private void subBytes(byte[][] state) {
        for (int row = 0; row < 4; row++)
            for (int col = 0; col < Nb; col++)
                state[row][col] = (byte) SBOX[state[row][col] & 0xFF];
    }

    // Odwrotność SubBytes – deszyfrowanie
    private void invSubBytes(byte[][] state) {
        for (int row = 0; row < 4; row++)
            for (int col = 0; col < Nb; col++)
                state[row][col] = (byte) INV_SBOX[state[row][col] & 0xFF];
    }

    // ShiftRows – cykliczne przesunięcie wierszy
    private void shiftRows(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] row = new byte[Nb];
            for (int c = 0; c < Nb; c++)
                row[c] = state[r][(c + r) % Nb];
            state[r] = row;
        }
    }

    // InvShiftRows – odwrotność przesunięcia
    private void invShiftRows(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] row = new byte[Nb];
            for (int c = 0; c < Nb; c++)
                row[(c + r) % Nb] = state[r][c];
            state[r] = row;
        }
    }

    // MixColumns – mieszanie kolumn w GF(2^8)
    private void mixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte a = state[0][c], b = state[1][c], d = state[2][c], e = state[3][c];
            state[0][c] = (byte)(mul(0x02,a) ^ mul(0x03,b) ^ d ^ e);
            state[1][c] = (byte)(a ^ mul(0x02,b) ^ mul(0x03,d) ^ e);
            state[2][c] = (byte)(a ^ b ^ mul(0x02,d) ^ mul(0x03,e));
            state[3][c] = (byte)(mul(0x03,a) ^ b ^ d ^ mul(0x02,e));
        }
    }

    // InvMixColumns – odwrotność mieszania kolumn
    private void invMixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte a = state[0][c], b = state[1][c], d = state[2][c], e = state[3][c];
            state[0][c] = (byte)(mul(0x0e,a) ^ mul(0x0b,b) ^ mul(0x0d,d) ^ mul(0x09,e));
            state[1][c] = (byte)(mul(0x09,a) ^ mul(0x0e,b) ^ mul(0x0b,d) ^ mul(0x0d,e));
            state[2][c] = (byte)(mul(0x0d,a) ^ mul(0x09,b) ^ mul(0x0e,d) ^ mul(0x0b,e));
            state[3][c] = (byte)(mul(0x0b,a) ^ mul(0x0d,b) ^ mul(0x09,d) ^ mul(0x0e,e));
        }
    }

    // Mnożenie w GF(2^8) – przez 2, 3, 0x0e itp.
    private byte mul(int a, byte b) {
        byte result = 0;
        byte temp = b;
        for (int i = 0; i < 8; i++) {
            if ((a & 1) != 0) result ^= temp;   // dodaj jeśli bit a jest ustawiony
            boolean high = (temp & 0x80) != 0;
            temp <<= 1;
            if (high) temp ^= 0x1b;             // redukcja po przepełnieniu (AES modulo)
            a >>= 1;
        }
        return result;
    }
}