#include <iostream>
#include <array>
#include <string>

using namespace std;

array<char, 16> hex2char(string h) {
    array <char, 16> result{ {0} };

    for (int i = 0; i < 32; i += 2) {
        string s = h.substr(i, 2);
        result[i / 2] = stoi(s, 0, 16);
    }

    return result;
};

class AES {

    const int Sbox[256] =
    {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    //const int InvSbox[256] = {
    //    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    //    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    //    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    //    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    //    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    //    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    //    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    //    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    //    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    //    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    //    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    //    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    //    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    //    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    //    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    //    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
    //};

    const int MixColumnsTable[4][4]{
        {2,3,1,1},
        {1,2,3,1},
        {1,1,2,3},
        {3,1,1,2}
    };

    //const int InvMixColumnsTable[4][4]{
    //    {14,11,13,9}, 
    //    {9,14,11,13}, 
    //    {13,9,14,11}, 
    //    {11,13,9,14}
    //};

    const char rc[10] = { (char)0x01, (char)0x02, (char)0x04, (char)0x08, (char)0x10, (char)0x20, (char)0x40, (char)0x80, (char)0x1B, (char)0x36 };

    array<char, 16> PrevBlock;
    array<char, 16> Key;

    array<array<char, 16>, 11> RoundKeys;

    void KeyExpansion() {
        RoundKeys[0] = Key;

        array<array<char, 4>, 4> SubKeys = {};

        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 16; j += 4)
                SubKeys[j / 4] = { RoundKeys[i][j], RoundKeys[i][j + 1], RoundKeys[i][j + 2], RoundKeys[i][j + 3] };

            array<char, 4> temp = SubKeys[3];
            temp = RotWord(temp);
            temp = SubWord(temp);
            temp = rcon(temp, i);

            array<array<char, 4>, 4> NewRoundSubKeys;
            for (int j = 0; j < 4; j++) {
                NewRoundSubKeys[j] = XorWord(SubKeys[j], temp);
                temp = NewRoundSubKeys[j];
            }

            for (int j = 0; j < 16; j++)
                RoundKeys[i + 1][j] = NewRoundSubKeys[j / 4][j % 4];
        }
    }

    char GaloisMult(char c1, char c2) {
        char32_t a = (unsigned char)c1;
        char32_t b = (unsigned char)c2;
        char32_t res = 0;
        while (a) {
            if (a & 1)
                res ^= b;
            a >>= 1;
            b <<= 1;
        }
        while (res > 0xFF)
        {
            char32_t newPoly = 0x11b;
            bool flag = false;
            while (newPoly <= res) {
                newPoly <<= 1;
                flag = true;
            }
            newPoly >>= flag ? 1 : 0;
            res ^= newPoly;
        }
        return (char)res;
    }

    array<char, 4> XorWord(array<char, 4> w1, array<char, 4> w2) {
        array<char, 4> result;
        for (int i = 0; i < 4; i++)
            result[i] = w1[i] ^ w2[i];
        return result;
    }

    array<char, 16> AddRoundKey(array<char, 16> block, int round) {
        for (int i = 0; i < 16; i++)
            block[i] ^= RoundKeys[round][i];
        return block;
    }

    array<char, 16> XorBlocks(array<char, 16> block1, array<char, 16> block2) {
        for (int i = 0; i < 16; i++)
            block1[i] ^= block2[i];
        return block1;
    }

    array<char, 4> SubWord(array<char, 4> subKey) {
        for (int i = 0; i < 4; i++) {
            int temp = (int)subKey[i] + 0x80;
            subKey[i] = Sbox[(unsigned char)subKey[i]];
        }
        return subKey;
    }

    array<char, 16> SubBlock(array<char, 16> block) {
        for (int i = 0; i < 16; i++) {
            int temp = (int)block[i] + 0x80;
            block[i] = Sbox[(unsigned char)block[i]];
        }
        return block;
    }

    //array<char, 16> InvSubBlock(array<char, 16> block) {
    //    for (int i = 0; i < 16; i++) {
    //        int temp = (int)block[i] + 0x80;
    //        block[i] = InvSbox[(unsigned char)block[i]];
    //    }
    //    return block;
    //}

    array<char, 4> RotWord(array<char, 4> subKey) {
        return array<char, 4> {subKey[1], subKey[2], subKey[3], subKey[0]};
    }

    array<char, 16> ShiftRows(array<char, 16> block) {
        for (int i = 1; i < 4; i++)
        {
            array<char, 4> subBlock;

            for (int j = 0; j < 4; j++)
                subBlock[j] = block[4 * j + i];

            subBlock = ShiftRow(subBlock, i);

            for (int j = 0; j < 4; j++)
                block[4 * j + i] = subBlock[j];
        }
        return block;
    }

    //array<char, 16> InvShiftRows(array<char, 16> block) {
    //    for (int i = 1; i < 4; i++)
    //    {
    //        array<char, 4> subBlock;
    //        for (int j = 0; j < 4; j++)
    //            subBlock[j] = block[4 * j + i];
    //        subBlock = ShiftRow(subBlock, 4-i);
    //        for (int j = 0; j < 4; j++)
    //            block[4 * j + i] = subBlock[j];
    //    }
    //    return block;
    //}

    array<char, 4> ShiftRow(array<char, 4> subBlock, int n) {
        array<char, 4> newSubBlock;
        for (int i = 0; i < 4; i++)
            newSubBlock[i] = subBlock[(i + n) % 4];
        return newSubBlock;
    }

    array<char, 16> MixColumns(array<char, 16> block) {
        for (int i = 0; i < 4; i++) {
            array<char, 4> subBlock;
            for (int j = 0; j < 4; j++)
                subBlock[j] = block[j + i * 4];

            subBlock = MixColumn(subBlock);

            for (int j = 0; j < 4; j++)
                block[j + i * 4] = subBlock[j];
        }
        return block;
    }

    //array<char, 16> InvMixColumns(array<char, 16> block) {
    //    for (int i = 0; i < 4; i++) {
    //        array<char, 4> subBlock;
    //        for (int j = 0; j < 4; j++)
    //            subBlock[j] = block[j + i * 4];
    //        subBlock = InvMixColumn(subBlock);
    //        for (int j = 0; j < 4; j++)
    //            block[j + i * 4] = subBlock[j];
    //    }
    //    return block;
    //}

    array<char, 4> MixColumn(array<char, 4> subBlock) {
        array<char, 4> newSubBlock;
        for (int i = 0; i < 4; i++)
        {
            newSubBlock[i] = GaloisMult(subBlock[0], MixColumnsTable[i][0]) ^ GaloisMult(subBlock[1], MixColumnsTable[i][1]) ^ GaloisMult(subBlock[2], MixColumnsTable[i][2]) ^ GaloisMult(subBlock[3], MixColumnsTable[i][3]);
        }
        return newSubBlock;
    }

    //array<char, 4> InvMixColumn(array<char, 4> subBlock) {
    //    array<char, 4> newSubBlock;
    //    for (int i = 0; i < 4; i++)
    //    {
    //        newSubBlock[i] = GaloisMult(subBlock[0], InvMixColumnsTable[i][0]) ^ GaloisMult(subBlock[1], InvMixColumnsTable[i][1]) ^ GaloisMult(subBlock[2], InvMixColumnsTable[i][2]) ^ GaloisMult(subBlock[3], InvMixColumnsTable[i][3]);
    //    }
    //    return newSubBlock;
    //}

    array<char, 4> rcon(array<char, 4> subKey, int i) {
        char new_char = subKey[0] ^ rc[i];
        return array<char, 4> {new_char, subKey[1], subKey[2], subKey[3]};
    }

    array<char, 16> EncryptBlock(array<char, 16> block) {
        block = AddRoundKey(block, 0);

        for (int i = 1; i < 10; i++)
        {
            block = SubBlock(block);
            block = ShiftRows(block);
            block = MixColumns(block);
            block = AddRoundKey(block, i);
        }

            block = SubBlock(block);
            block = ShiftRows(block);
            block = AddRoundKey(block, 10);
        return block;
    }

    //array<char, 16> DecryptBlock(array<char, 16> block) {
    //    block = AddRoundKey(block, 10);
    //    for (int i = 9; i > 0; i--)
    //    {
    //        block = InvShiftRows(block);
    //        block = InvSubBlock(block);
    //        block = AddRoundKey(block, i);
    //        block = InvMixColumns(block);
    //    }
    //    block = InvShiftRows(block);
    //    block = InvSubBlock(block);
    //    block = AddRoundKey(block, 0);
    //    return block;
    //}

public:
    AES(array<char, 16> IV, array<char, 16> Key) {
        this->PrevBlock = IV;
        this->Key = Key;

        KeyExpansion();
    }

    void prettyPrintRoundKeys() {
        for (int i = 0; i < 11; i++) {
            for (int j = 0; j < 16; j++)
            {
                printf("%02x", (int)(unsigned char)RoundKeys[i][j]);
                if (j % 4 == 3)
                    printf(" ");
            }
            printf("\n");
        }
    }

    void Encrypt(string Data) {
        for (int i = 0; i <= Data.length(); i+=32)
        {
            string blockString = Data.substr(i, 32);
            array<char, 16> block;

            if (blockString.length() < 32) {
                int l = blockString.length();
                for (int j = l; j < 32; j++)
                    blockString.append("0");
                block = hex2char(blockString);      
                block = XorBlocks(block, EncryptBlock(PrevBlock));
                for (int i = 0; i < l/2 ; i++) { 
                    printf("%02x", (int)(unsigned char)block[i]);
                    if (i % 4 == 3)
                        printf(" ");
                }
                printf("\n");
            }
            else {
                block = hex2char(blockString);
                block = XorBlocks(block, EncryptBlock(PrevBlock));
                for (int i = 0; i < 16; i++) {
                    printf("%02x", (int)(unsigned char)block[i]);
                    if (i % 4 == 3)
                        printf(" ");
                }
                PrevBlock = block;
            }
        }
    }



    void Decrypt(string Data) {
        for (int i = 0; i <= Data.length(); i += 32)
        {
            string blockString = Data.substr(i, 32);
            array<char, 16> block;

            if (blockString.length() < 32) {
                int l = blockString.length();
                for (int j = l; j < 32; j++)
                    blockString.append("0");
                block = hex2char(blockString);
                block = XorBlocks(block, EncryptBlock(PrevBlock));
                for (int i = 0; i < l / 2; i++) {
                    printf("%02x", (int)(unsigned char)block[i]);
                    if (i % 4 == 3)
                        printf(" ");
                }
                printf("\n");
            }
            else {
                block = hex2char(blockString);
                array<char, 16> new_block = EncryptBlock(PrevBlock);

                PrevBlock = block;

                new_block = XorBlocks(new_block, block);
                for (int i = 0; i < 16; i++) {
                    printf("%02x", (int)(unsigned char)new_block[i]);
                    if (i % 4 == 3)
                        printf(" ");
                }
            }
        }
    }
};

int main()
{
    string Key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    string IV_hex = "000102030405060708090a0b0c0d0e0f"; 
    array<char, 16> Key = hex2char(Key_hex);
    array<char, 16> IV = hex2char(IV_hex);


    //6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
    string Data_hex_enc = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaffed";
    AES enc = AES(IV, Key);
    printf("Round keys:\n");
    enc.prettyPrintRoundKeys();

    printf("\n--------------\n\n");

    printf("Encrypt:\n");

    enc.Encrypt(Data_hex_enc);

    printf("\n--------------\n\n");
    AES dec = AES(IV, Key);

    printf("Decrypt:\n");
    string Data_hex_dec = "fa54cd6633c7981c70a39d43310546ca78fa651c52d861158ffd478c6f30e3776eee";

    dec.Decrypt(Data_hex_dec);

}
