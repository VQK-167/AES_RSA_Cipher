const $ = id => document.getElementById(id);

const cipherType = $("cipherType");
const plainText = $("plainText");
const cipherText = $("cipherText");
const encryptBtn = $("encryptBtn");
const decryptBtn = $("decryptBtn");

const alphabet26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const alphabet29 = "AĂÂBCDĐEÊGHIKLMNOÔƠPQRSTUƯVXY";

// =========================
// AES - CHUYỂN CHỮ → BIT
// =========================

function textToBinary(text) {
    const bytes = new TextEncoder().encode(text);

    return Array.from(bytes)
        .map(byte => byte.toString(2).padStart(8, "0"))
        .join("");
}

// =========================
// AES - LẤY KHÓA 128 BIT
// =========================

function getAESKeyBits() {
    const key = $("aesKeyInput").value;

    if (key.length !== 16) {
        throw new Error("Khóa AES-128 phải có đúng 16 ký tự!");
    }

    const keyBits = textToBinary(key);

    if (keyBits.length !== 128) {
        throw new Error("Khóa AES phải có đúng 128 bit!");
    }

    return keyBits;
}

// =========================
// AES - RCON
// =========================

const AES_RCON = [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36
];

function xorWord(a, b) {
    return [
        a[0] ^ b[0],
        a[1] ^ b[1],
        a[2] ^ b[2],
        a[3] ^ b[3]
    ];
}
function rotWord(word) {
    return [
        word[1],
        word[2],
        word[3],
        word[0]
    ];
}
// =========================
// AES - S-BOX
// =========================

const AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,

    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,

    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,

    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,

    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,

    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,

    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,

    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,

    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,

    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,

    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,

    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,

    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,

    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,

    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// =========================
// AES - INVERSE S-BOX
// =========================

const AES_INV_SBOX = new Array(256);

for (let i = 0; i < 256; i++) {
    AES_INV_SBOX[AES_SBOX[i]] = i;
}

function subWord(word) {
    return word.map(byte => AES_SBOX[byte]);
}
// =========================
// AES-128 - KEY EXPANSION
// =========================

function aesKeyExpansion(keyBytes) {
    if (keyBytes.length !== 16) {
        throw new Error("Khóa AES-128 phải có 16 byte!");
    }

    const words = [];

    // 4 word đầu tiên lấy từ khóa ban đầu
    for (let i = 0; i < 4; i++) {
        words[i] = [
            keyBytes[i * 4],
            keyBytes[i * 4 + 1],
            keyBytes[i * 4 + 2],
            keyBytes[i * 4 + 3]
        ];
    }

    // Sinh 40 word tiếp theo
    for (let i = 4; i < 44; i++) {

        let temp = [...words[i - 1]];

        if (i % 4 === 0) {
            temp = rotWord(temp);
            temp = subWord(temp);

            temp[0] ^= AES_RCON[i / 4];
        }

        words[i] = xorWord(words[i - 4], temp);
    }

    return words;
}
function aesKeyToBytes(key) {
    const bytes = new TextEncoder().encode(key);

    if (bytes.length !== 16) {
        throw new Error("Khóa AES-128 phải có đúng 16 byte!");
    }

    return Array.from(bytes);
}
// =========================
// AES - TẠO STATE 4x4
// =========================

function aesCreateState(bytes) {
    if (bytes.length !== 16) {
        throw new Error("AES State phải có đúng 16 byte!");
    }

    const state = Array.from({ length: 4 }, () => Array(4).fill(0));

    // AES ghi dữ liệu theo cột
    for (let i = 0; i < 16; i++) {
        const row = i % 4;
        const col = Math.floor(i / 4);

        state[row][col] = bytes[i];
    }

    return state;
}
// =========================
// AES - ADD ROUND KEY
// =========================

function aesAddRoundKey(state, roundKey) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    for (let row = 0; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            result[row][col] =
                state[row][col] ^ roundKey[row][col];
        }
    }

    return result;
}
// =========================
// AES - SUB BYTES
// =========================

function aesSubBytes(state) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    for (let row = 0; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            result[row][col] = AES_SBOX[state[row][col]];
        }
    }

    return result;
}
// =========================
// AES - INVERSE SUB BYTES
// =========================

function aesInvSubBytes(state) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    for (let row = 0; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            result[row][col] =
                AES_INV_SBOX[state[row][col]];
        }
    }

    return result;
}
// =========================
// AES - INVERSE SHIFT ROWS
// =========================

function aesInvShiftRows(state) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    // Hàng 0: giữ nguyên
    result[0] = [...state[0]];

    // Hàng 1: dịch phải 1
    result[1] = [
        state[1][3],
        state[1][0],
        state[1][1],
        state[1][2]
    ];

    // Hàng 2: dịch phải 2
    result[2] = [
        state[2][2],
        state[2][3],
        state[2][0],
        state[2][1]
    ];

    // Hàng 3: dịch phải 3
    result[3] = [
        state[3][1],
        state[3][2],
        state[3][3],
        state[3][0]
    ];

    return result;
}
// =========================
// AES - INVERSE MIX COLUMNS
// =========================

function aesInvMixColumns(state) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    for (let col = 0; col < 4; col++) {

        const a0 = state[0][col];
        const a1 = state[1][col];
        const a2 = state[2][col];
        const a3 = state[3][col];

        result[0][col] =
            aesGmul(a0, 14) ^
            aesGmul(a1, 11) ^
            aesGmul(a2, 13) ^
            aesGmul(a3, 9);

        result[1][col] =
            aesGmul(a0, 9) ^
            aesGmul(a1, 14) ^
            aesGmul(a2, 11) ^
            aesGmul(a3, 13);

        result[2][col] =
            aesGmul(a0, 13) ^
            aesGmul(a1, 9) ^
            aesGmul(a2, 14) ^
            aesGmul(a3, 11);

        result[3][col] =
            aesGmul(a0, 11) ^
            aesGmul(a1, 13) ^
            aesGmul(a2, 9) ^
            aesGmul(a3, 14);
    }

    return result;
}

// =========================
// AES - ENCRYPT ROUND
// =========================

function aesEncryptRound(state, roundKey, isFinalRound = false) {
    // Bước 1: SubBytes
    let result = aesSubBytes(state);

    // Bước 2: ShiftRows
    result = aesShiftRows(result);

    // Bước 3: MixColumns
    // Không thực hiện MixColumns ở vòng cuối
    if (!isFinalRound) {
        result = aesMixColumns(result);
    }

    // Bước 4: AddRoundKey
    result = aesAddRoundKey(result, roundKey);

    return result;
}

// =========================
// AES - ENCRYPT BLOCK
// =========================

function aesEncryptBlock(plaintextBytes, keyBytes) {
    // AES-128: plaintext phải có 16 byte
    if (plaintextBytes.length !== 16) {
        throw new Error("AES chỉ mã hóa block 16 byte!");
    }

    // AES-128: khóa phải có 16 byte
    if (keyBytes.length !== 16) {
        throw new Error("AES-128 cần khóa 16 byte!");
    }

    // 1. Sinh 44 word khóa
    const words = aesKeyExpansion(keyBytes);

    // 2. Chuyển plaintext thành State 4x4
    let state = aesCreateState(plaintextBytes);

    // 3. Vòng 0: AddRoundKey
    let roundKey = aesGetRoundKey(words, 0);
    state = aesAddRoundKey(state, roundKey);

    // 4. Vòng 1 → 9
    for (let round = 1; round <= 9; round++) {
        roundKey = aesGetRoundKey(words, round);

        state = aesEncryptRound(
            state,
            roundKey,
            false
        );
    }

    // 5. Vòng 10: vòng cuối
    // Không thực hiện MixColumns
    roundKey = aesGetRoundKey(words, 10);

    state = aesEncryptRound(
        state,
        roundKey,
        true
    );

    // 6. Trả về State sau khi mã hóa
    return state;
}

// =========================
// AES - SHIFT ROWS
// =========================

function aesShiftRows(state) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    // Hàng 0: giữ nguyên
    result[0] = [...state[0]];

    // Hàng 1: dịch trái 1
    result[1] = [
        state[1][1],
        state[1][2],
        state[1][3],
        state[1][0]
    ];

    // Hàng 2: dịch trái 2
    result[2] = [
        state[2][2],
        state[2][3],
        state[2][0],
        state[2][1]
    ];

    // Hàng 3: dịch trái 3
    result[3] = [
        state[3][3],
        state[3][0],
        state[3][1],
        state[3][2]
    ];

    return result;
}
// =========================
// AES - NHÂN TRONG GF(2^8)
// =========================

function aesGmul(a, b) {
    let result = 0;

    for (let i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }

        const highBit = a & 0x80;

        a = (a << 1) & 0xFF;

        if (highBit) {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return result;
}
// =========================
// AES - MIX COLUMNS
// =========================

function aesMixColumns(state) {
    const result = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    for (let col = 0; col < 4; col++) {

        const a0 = state[0][col];
        const a1 = state[1][col];
        const a2 = state[2][col];
        const a3 = state[3][col];

        result[0][col] =
            aesGmul(a0, 2) ^
            aesGmul(a1, 3) ^
            a2 ^
            a3;

        result[1][col] =
            a0 ^
            aesGmul(a1, 2) ^
            aesGmul(a2, 3) ^
            a3;

        result[2][col] =
            a0 ^
            a1 ^
            aesGmul(a2, 2) ^
            aesGmul(a3, 3);

        result[3][col] =
            aesGmul(a0, 3) ^
            a1 ^
            a2 ^
            aesGmul(a3, 2);
    }

    return result;
}
// =========================
// AES - LẤY ROUND KEY
// =========================

function aesGetRoundKey(words, round) {
    const key = Array.from(
        { length: 4 },
        () => Array(4).fill(0)
    );

    const start = round * 4;

    for (let col = 0; col < 4; col++) {
        const word = words[start + col];

        for (let row = 0; row < 4; row++) {
            key[row][col] = word[row];
        }
    }

    return key;
}
// =========================
// AES-128 - GIẢI MÃ
// =========================

function aesDecryptBlock(ciphertextBytes, keyBytes) {

    if (ciphertextBytes.length !== 16) {
        throw new Error("AES cần ciphertext 16 byte!");
    }

    if (keyBytes.length !== 16) {
        throw new Error("AES-128 cần khóa 16 byte!");
    }

    // Sinh khóa vòng
    const words = aesKeyExpansion(keyBytes);

    // Ciphertext → State
    let state = aesCreateState(ciphertextBytes);

    // =========================
    // Bước đầu: AddRoundKey K10
    // =========================

    state = aesAddRoundKey(
        state,
        aesGetRoundKey(words, 10)
    );

    // =========================
    // Round 9 → Round 1
    // =========================

    for (let round = 9; round >= 1; round--) {

        // 1. InvShiftRows
        state = aesInvShiftRows(state);

        // 2. InvSubBytes
        state = aesInvSubBytes(state);

        // 3. AddRoundKey
        state = aesAddRoundKey(
            state,
            aesGetRoundKey(words, round)
        );

        // 4. InvMixColumns
        state = aesInvMixColumns(state);
    }

    // =========================
    // Round cuối
    // =========================

    // 1. InvShiftRows
    state = aesInvShiftRows(state);

    // 2. InvSubBytes
    state = aesInvSubBytes(state);

    // 3. AddRoundKey K0
    state = aesAddRoundKey(
        state,
        aesGetRoundKey(words, 0)
    );

    return state;
}


// =========================
// AES - STATE → BYTES
// =========================

function aesStateToBytes(state) {
    const bytes = [];

    // AES đọc State theo cột
    for (let col = 0; col < 4; col++) {
        for (let row = 0; row < 4; row++) {
            bytes.push(state[row][col]);
        }
    }

    return bytes;
}
// =========================
// AES - BYTES → HEX
// =========================

function aesBytesToHex(bytes) {
    return bytes
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
}

// ================= RSA =================

function rsaGCD(a, b) {
    while (b !== 0n) {
        let temp = a % b;
        a = b;
        b = temp;
    }
    return a;
}

function rsaModPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;

    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }

        base = (base * base) % mod;
        exp = exp / 2n;
    }

    return result;
}

function rsaModInverse(e, phi) {
    let oldR = e;
    let r = phi;

    let oldS = 1n;
    let s = 0n;

    while (r !== 0n) {
        let q = oldR / r;

        [oldR, r] = [
            r,
            oldR - q * r
        ];

        [oldS, s] = [
            s,
            oldS - q * s
        ];
    }

    if (oldR !== 1n) {
        throw new Error("e không có nghịch đảo modulo phi(n)!");
    }

    return (oldS % phi + phi) % phi;
}

// Kiểm tra số nguyên tố (Miller-Rabin)
function rsaIsPrime(n) {
    if (n < 2n) return false;

    const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

    for (const b of bases) {
        if (n === b) return true;
        if (n % b === 0n) return false;
    }

    let d = n - 1n;
    let r = 0;

    while (d % 2n === 0n) {
        d /= 2n;
        r++;
    }

    for (const a of bases) {
        let x = rsaModPow(a, d, n);

        if (x === 1n || x === n - 1n) continue;

        let composite = true;

        for (let i = 1; i < r; i++) {
            x = (x * x) % n;
            if (x === n - 1n) {
                composite = false;
                break;
            }
        }

        if (composite) return false;
    }

    return true;
}

function rsaGenerateKeys(p, q, e) {
    p = BigInt(p);
    q = BigInt(q);
    e = BigInt(e);

    if (p < 2n || q < 2n || e < 2n) {
        throw new Error("p, q và e phải lớn hơn 1!");
    }

    if (p === q) {
        throw new Error("p và q phải khác nhau!");
    }

    if (!rsaIsPrime(p) || !rsaIsPrime(q)) {
        throw new Error("p và q phải là số nguyên tố!");
    }

    const n = p * q;
    const phi = (p - 1n) * (q - 1n);

    if (n <= 255n) {
        throw new Error("n = p·q phải lớn hơn 255 để mã hóa được từng byte ký tự!");
    }

    if (e >= phi) {
        throw new Error("e phải thỏa 1 < e < φ(n)!");
    }

    if (rsaGCD(e, phi) !== 1n) {
        throw new Error("e không nguyên tố cùng nhau với phi(n)!");
    }

    const d = rsaModInverse(e, phi);

    return {
        n,
        phi,
        e,
        d
    };
}

function rsaEncryptNumber(m, e, n) {
    return rsaModPow(
        BigInt(m),
        BigInt(e),
        BigInt(n)
    );
}

function rsaDecryptNumber(c, d, n) {
    return rsaModPow(
        BigInt(c),
        BigInt(d),
        BigInt(n)
    );
}
// ================= RSA TEXT =================

function rsaEncryptText(text, e, n) {
    const bytes = new TextEncoder().encode(text);

    return Array.from(bytes).map(byte =>
        rsaEncryptNumber(byte, e, n).toString()
    );
}

function rsaDecryptText(ciphertext, d, n) {
    const bytes = ciphertext.map(value =>
        Number(
            rsaDecryptNumber(
                BigInt(value),
                d,
                n
            )
        )
    );

    if (bytes.some(b => b > 255)) {
        throw new Error("Giải mã thất bại: sai khóa hoặc bản mã không hợp lệ!");
    }

    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(
            new Uint8Array(bytes)
        );
    } catch {
        throw new Error("Giải mã thất bại: sai khóa hoặc bản mã không hợp lệ!");
    }
}

// DES - Initial Permutation
const IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];
// DES - Final Permutation
const IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
];
// DES - Permuted Choice 1
const PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
];
// DES - Permuted Choice 2
const PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];
// DES - Left shifts for each round
const SHIFTS = [
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
];
// DES - Expansion table
const E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
];

// DES - Permutation P
const P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
];
// DES - 8 S-Boxes
const S_BOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],

    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],

    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],

    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
];
// DES - Chuyển Hex sang Binary
function hexToBinary(hex) {
    return hex
        .split("")
        .map(char => parseInt(char, 16).toString(2).padStart(4, "0"))
        .join("");
}

// DES - Chuyển Binary sang Hex
function binaryToHex(binary) {
    let hex = "";

    for (let i = 0; i < binary.length; i += 4) {
        const group = binary.substring(i, i + 4);
        hex += parseInt(group, 2).toString(16).toUpperCase();
    }

    return hex;
}

// DES - Hoán vị theo bảng
function permute(bits, table) {
    return table.map(position => bits[position - 1]).join("");
}
// DES - Tạo 16 khóa vòng
function generateRoundKeys(keyHex) {
    const keyBits = hexToBinary(keyHex);

    // Bước 1: PC1
    const permutedKey = permute(keyBits, PC1);

    // Bước 2: Chia thành C0 và D0
    let C = permutedKey.substring(0, 28);
    let D = permutedKey.substring(28, 56);

    const roundKeys = [];

    // Bước 3: Tạo K1 đến K16
    for (let i = 0; i < 16; i++) {
        C = leftShift(C, SHIFTS[i]);
        D = leftShift(D, SHIFTS[i]);

        const combined = C + D;

        const roundKey = permute(combined, PC2);

        roundKeys.push(roundKey);
    }

    return roundKeys;
}

// DES - Dịch trái
function leftShift(bits, count) {
    return bits.substring(count) + bits.substring(0, count);
}
// DES - Hàm F
function desFunction(R, roundKey) {
    // Bước 1: Mở rộng R từ 32 bit lên 48 bit
    const expandedR = permute(R, E);

    // Bước 2: XOR với khóa vòng
    let xored = "";

    for (let i = 0; i < 48; i++) {
        xored += expandedR[i] === roundKey[i] ? "0" : "1";
    }

    // Bước 3: Chia thành 8 nhóm, mỗi nhóm 6 bit
    let sBoxOutput = "";

    for (let i = 0; i < 8; i++) {
        const block = xored.substring(i * 6, i * 6 + 6);

        // Bit đầu và bit cuối xác định hàng
        const row = parseInt(
            block[0] + block[5],
            2
        );

        // 4 bit giữa xác định cột
        const column = parseInt(
            block.substring(1, 5),
            2
        );

        // Lấy giá trị từ S-Box
        const value = S_BOX[i][row][column];

        // Đổi giá trị thành 4 bit
        sBoxOutput += value
            .toString(2)
            .padStart(4, "0");
    }

    // Bước 4: Hoán vị P
    const result = permute(sBoxOutput, P);

    return result;
}
// DES - Thực hiện 16 vòng
function desRounds(L, R, roundKeys) {
    for (let i = 0; i < 16; i++) {
        const oldR = R;

        // R mới = L cũ XOR F(R cũ, K)
        const fResult = desFunction(R, roundKeys[i]);

        let newR = "";

        for (let j = 0; j < 32; j++) {
            newR += L[j] === fResult[j] ? "0" : "1";
        }

        // L mới = R cũ
        L = oldR;

        // R mới
        R = newR;
    }

    return {
        L,
        R
    };
}
// DES - Mã hóa một khối 64 bit
function desEncrypt(plainHex, keyHex) {
    // Bước 1: Đổi bản rõ và khóa từ Hex sang Binary
    const plainBits = hexToBinary(plainHex);

    // Bước 2: Sinh 16 khóa vòng
    const roundKeys = generateRoundKeys(keyHex);

    // Bước 3: Thực hiện hoán vị IP
    const initialPermutation = permute(plainBits, IP);

    // Bước 4: Chia thành L0 và R0
    let L = initialPermutation.substring(0, 32);
    let R = initialPermutation.substring(32, 64);

    // Bước 5: Thực hiện 16 vòng DES
    const result = desRounds(L, R, roundKeys);

    L = result.L;
    R = result.R;

    // Bước 6: Đảo vị trí R16 và L16
    const combined = R + L;

    // Bước 7: Thực hiện hoán vị cuối IP^-1
    const cipherBits = permute(combined, IP_INV);

    // Bước 8: Đổi Binary sang Hex
    return binaryToHex(cipherBits);
}
// DES - Giải mã một khối 64 bit
function desDecrypt(cipherHex, keyHex) {
    // Bước 1: Đổi bản mã từ Hex sang Binary
    const cipherBits = hexToBinary(cipherHex);

    // Bước 2: Sinh 16 khóa vòng
    const roundKeys = generateRoundKeys(keyHex);

    // Bước 3: Đảo thứ tự khóa
    roundKeys.reverse();

    // Bước 4: Thực hiện hoán vị IP
    const initialPermutation = permute(cipherBits, IP);

    // Bước 5: Chia thành L0 và R0
    let L = initialPermutation.substring(0, 32);
    let R = initialPermutation.substring(32, 64);

    // Bước 6: Thực hiện 16 vòng DES
    const result = desRounds(L, R, roundKeys);

    L = result.L;
    R = result.R;

    // Bước 7: Đảo vị trí
    const combined = R + L;

    // Bước 8: Hoán vị cuối
    const plainBits = permute(combined, IP_INV);

    // Bước 9: Binary → Hex
    return binaryToHex(plainBits);
}

// =========================
// AES - MÃ HÓA / GIẢI MÃ VĂN BẢN
// (ECB + đệm PKCS#7, kết quả dạng Hex)
// =========================

function aesEncryptText(text, key) {
    const keyBytes = aesKeyToBytes(key);
    const data = Array.from(new TextEncoder().encode(text));

    const padLen = 16 - (data.length % 16);
    for (let i = 0; i < padLen; i++) {
        data.push(padLen);
    }

    const out = [];
    for (let i = 0; i < data.length; i += 16) {
        const block = data.slice(i, i + 16);
        out.push(...aesStateToBytes(aesEncryptBlock(block, keyBytes)));
    }

    return aesBytesToHex(out);
}

function aesDecryptText(hex, key) {
    hex = hex.replace(/\s+/g, "");

    if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length % 32 !== 0) {
        throw new Error("Bản mã AES phải là chuỗi Hex, độ dài là bội số của 32 ký tự!");
    }

    const keyBytes = aesKeyToBytes(key);
    const bytes = hex.match(/../g).map(h => parseInt(h, 16));

    let out = [];
    for (let i = 0; i < bytes.length; i += 16) {
        const block = bytes.slice(i, i + 16);
        out.push(...aesStateToBytes(aesDecryptBlock(block, keyBytes)));
    }

    const padLen = out[out.length - 1];
    if (padLen < 1 || padLen > 16 || !out.slice(-padLen).every(b => b === padLen)) {
        throw new Error("Giải mã thất bại: sai khóa hoặc bản mã không hợp lệ!");
    }
    out = out.slice(0, -padLen);

    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(out));
    } catch {
        throw new Error("Giải mã thất bại: sai khóa hoặc bản mã không hợp lệ!");
    }
}

const keyInputs = {
    caesar: $("caesarKey"),
    substitution: $("substitutionKey"),
    vigenere: $("vigenereKey"),
    affine: $("affineKey"),
    hill: $("hillKey"),
    des: $("desKey"),
    aes: $("aesKey"),
    rsa: $("rsaInputs")
};

function getAlphabet() {
    const selected = document.querySelector(
        'input[name="alphabet"]:checked'
    );

    return selected && selected.value === "29"
        ? alphabet29
        : alphabet26;
}

function mod(n, m) {
    return ((n % m) + m) % m;
}

function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);
    while (b !== 0) {
        [a, b] = [b, a % b];
    }
    return a;
}

function modInverse(a, m) {
    a = mod(a, m);
    for (let x = 1; x < m; x++) {
        if (mod(a * x, m) === 1) {
            return x;
        }
    }
    return -1;
}
function getNumber(id) {
    const input = $(id);
    if (!input || input.value === "") {
        throw new Error("Vui lòng nhập đầy đủ khóa!");
    }
    const value = Number(input.value);
    if (!Number.isInteger(value)) {
        throw new Error("Khóa phải là số nguyên!");
    }
    return value;
}
function validateDESHex(value) {
    return /^[0-9A-Fa-f]{16}$/.test(value.trim());
}
function getIndex(char, alphabet) {
    return alphabet.indexOf(char.toUpperCase());
}

function transformText(text, transform, alphabet) {
    return [...text].map(char => {
        const index = getIndex(char, alphabet);
        if (index === -1) {
            return char;
        }
        const newIndex = mod(
            transform(index),
            alphabet.length
        );
        const newChar = alphabet[newIndex];
        return char === char.toLowerCase()
            ? newChar.toLowerCase()
            : newChar;
    }).join("");
}

function updateKeyInput() {
    const type = cipherType.value;
    const isClassical = ["caesar", "substitution", "vigenere", "affine", "hill"].includes(type);
    const isHash = ["md5", "sha"].includes(type);

    // Z26/Z29 chỉ dùng cho mã cổ điển
    $("alphabetGroup").classList.toggle("hidden", !isClassical);
    // Hàm băm không có khóa và không có giải mã
    $("keyGroup").classList.toggle("hidden", isHash);
    decryptBtn.classList.toggle("hidden", isHash);

    Object.entries(keyInputs).forEach(
        ([type, element]) => {
            element.classList.toggle(
                "hidden",
                cipherType.value !== type
            );
        }
    );
}

cipherType.addEventListener(
    "change",
    updateKeyInput
);

function caesar(text, key, decrypt, alphabet) {
    const m = alphabet.length;
    key = mod(key, m);
    if (decrypt) {
        key = -key;
    }
    return transformText(
        text,
        index => index + key,
        alphabet
    );
}

function validateSubstitutionKey(key, alphabet) {
    key = key.trim().toUpperCase();
    return (
        key.length === alphabet.length &&
        [...key].every(
            char => alphabet.includes(char)
        ) &&
        new Set(key).size === alphabet.length
    );
}

function substitution(
    text,
    key,
    decrypt,
    alphabet
) {
    key = key.trim().toUpperCase();
    return transformText(
        text,
        index => {
            if (!decrypt) {
                return alphabet.indexOf(key[index]);
            }
            return key.indexOf(alphabet[index]);
        },
        alphabet
    );
}

function validateVigenereKey(key, alphabet) {
    key = key.trim().toUpperCase();
    return (
        key.length > 0 &&
        [...key].every(
            char => alphabet.includes(char)
        )
    );
}

function vigenere(
    text,
    key,
    decrypt,
    alphabet
) {
    key = key.trim().toUpperCase();
    const m = alphabet.length;
    let keyIndex = 0;
    return [...text].map(char => {
        const textIndex =
            getIndex(char, alphabet);

        if (textIndex === -1) {
            return char;
        }
        const keyChar =
            key[keyIndex % key.length];
        const keyValue =
            alphabet.indexOf(keyChar);
        keyIndex++;
        const value = decrypt
            ? textIndex - keyValue
            : textIndex + keyValue;
        const newChar =
            alphabet[mod(value, m)];
        return char === char.toLowerCase()
            ? newChar.toLowerCase()
            : newChar;
    }).join("");
}

function validateAffineKey(a, b, alphabet) {
    return (
        Number.isInteger(a) &&
        Number.isInteger(b) &&
        gcd(a, alphabet.length) === 1
    );
}

function affine(
    text,
    a,
    b,
    decrypt,
    alphabet
) {
    const m = alphabet.length;
    a = mod(a, m);
    b = mod(b, m);
    if (!decrypt) {
        return transformText(
            text,
            index => a * index + b,
            alphabet
        );
    }
    const inverseA =
        modInverse(a, m);
    if (inverseA === -1) {
        throw new Error(
            "Không tìm được nghịch đảo của a!"
        );
    }
    return transformText(
        text,
        index =>
            inverseA * (index - b),
        alphabet
    );
}

function validateHillKey(
    a,
    b,
    c,
    d,
    alphabet
) {
    const determinant =
        a * d - b * c;
    return gcd(
        determinant,
        alphabet.length
    ) === 1;
}

function hill(
    text,
    a,
    b,
    c,
    d,
    decrypt,
    alphabet
) {
    const m = alphabet.length;
    if (!validateHillKey(
        a,
        b,
        c,
        d,
        alphabet
    )) {
        throw new Error(
            `Ma trận khóa không hợp lệ trong Z${m}! ` +
            `Cần gcd(det, ${m}) = 1.`
        );
    }
    if (decrypt) {
        const determinant =
            a * d - b * c;
        const inverseDet =
            modInverse(
                determinant,
                m
            );
        const oldA = a;
        const oldB = b;
        const oldC = c;
        const oldD = d;
        a = mod(
            inverseDet * oldD,
            m
        );
        b = mod(
            inverseDet * (-oldB),
            m
        );
        c = mod(
            inverseDet * (-oldC),
            m
        );
        d = mod(
            inverseDet * oldA,
            m
        );
    }
    let cleanText = [...text]
        .map(char => char.toUpperCase())
        .filter(
            char => alphabet.includes(char)
        )
        .join("");
    if (
        !decrypt &&
        cleanText.length % 2 !== 0
    ) {
        cleanText += "X";
    }
    if (
        decrypt &&
        cleanText.length % 2 !== 0
    ) {
        throw new Error(
            "Bản mã Hill phải có số ký tự chẵn!"
        );
    }
    let result = "";
    for (
        let i = 0;
        i < cleanText.length;
        i += 2
    ) {
        const x1 =
            alphabet.indexOf(cleanText[i]);
        const x2 =
            alphabet.indexOf(cleanText[i + 1]);
        const y1 =
            mod(
                a * x1 + b * x2,
                m
            );
        const y2 =
            mod(
                c * x1 + d * x2,
                m
            );
        result += alphabet[y1];
        result += alphabet[y2];
    }
    return result;
}

function getHillKey() {
    return [
        getNumber("hill11"),
        getNumber("hill12"),
        getNumber("hill21"),
        getNumber("hill22")
    ];
}

function processCipher(decrypt = false) {
    const type = cipherType.value;
    const alphabet = getAlphabet();
    const m = alphabet.length;
    let input = decrypt
        ? cipherText.value
        : plainText.value;
    if (input.trim() === "") {
        throw new Error(
            decrypt
                ? "Vui lòng nhập bản mã!"
                : "Vui lòng nhập bản rõ!"
        );
    }
    let result;

    // Chuẩn hóa tiếng Việt (tổ hợp/dựng sẵn) để so khớp đúng với bảng chữ cái
    if (["caesar", "substitution", "vigenere", "affine", "hill"].includes(type)) {
        input = input.normalize("NFC");
    }

    if (type === "caesar") {
        const key = getNumber("shiftKey");
        result = caesar(
            input,
            key,
            decrypt,
            alphabet
        );
    }

    else if (type === "substitution") {
        const key =
            $("substitutionAlphabet").value;
        if (
            !validateSubstitutionKey(
                key,
                alphabet
            )
        ) {
            throw new Error(
                `Khóa thay thế Z${m} phải có ` +
                `${m} ký tự, chỉ chứa ký tự ` +
                `trong bảng chữ cái và không được trùng!`
            );
        }
        result = substitution(
            input,
            key,
            decrypt,
            alphabet
        );
    }
    else if (type === "vigenere") {
        const key =
            $("vigenereKeyword").value;
        if (
            !validateVigenereKey(
                key,
                alphabet
            )
        ) {
            throw new Error(
                `Khóa Vigenere Z${m} không hợp lệ!`
            );
        }
        result = vigenere(
            input,
            key,
            decrypt,
            alphabet
        );
    }
    else if (type === "affine") {
        const a = getNumber("affineA");
        const b = getNumber("affineB");
        if (
            !validateAffineKey(
                a,
                b,
                alphabet
            )
        ) {
            throw new Error(
                `Khóa Affine không hợp lệ trong Z${m}! ` +
                `Cần gcd(a, ${m}) = 1.`
            );
        }
        result = affine(
            input,
            a,
            b,
            decrypt,
            alphabet
        );
    }
    else if (type === "hill") {
        const [a, b, c, d] =
            getHillKey();

        result = hill(
            input,
            a,
            b,
            c,
            d,
            decrypt,
            alphabet
        );
    }
    else if (type === "des") {
        const key = $("desKeyInput").value.trim();

        const input = decrypt
            ? cipherText.value.trim()
            : plainText.value.trim();

        if (!validateDESHex(key)) {
            alert("Khóa DES phải gồm đúng 16 ký tự Hex.");
            return;
        }

        if (!validateDESHex(input)) {
            alert(
                decrypt
                    ? "Bản mã DES phải gồm đúng 16 ký tự Hex."
                    : "Bản rõ DES phải gồm đúng 16 ký tự Hex."
            );
            return;
        }

        if (decrypt) {
            plainText.value = desDecrypt(input, key);
        } else {
            cipherText.value = desEncrypt(input, key);
        }

        return;
    }
    else if (type === "aes") {
        const key = $("aesKeyInput").value;

        if (decrypt) {
            result = aesDecryptText(input, key);
        } else {
            result = aesEncryptText(input, key);
        }
    }
    else if (type === "md5" || type === "sha") {
        throw new Error("Hàm băm MD5/SHA chưa được cài đặt!");
    }
    else if (type === "rsa") {

        const p = $("rsaP").value.trim();
        const q = $("rsaQ").value.trim();
        const e = $("rsaE").value.trim();

        if (!p || !q || !e) {
            throw new Error("Vui lòng nhập p, q và e!");
        }

        if (![p, q, e].every(v => /^\d+$/.test(v))) {
            throw new Error("p, q và e phải là số nguyên dương!");
        }

        const keys = rsaGenerateKeys(p, q, e);

        if (!decrypt) {

            result = rsaEncryptText(
                input,
                keys.e,
                keys.n
            ).join(" ");

        } else {

            const ciphertext = input
                .trim()
                .split(/\s+/);

            if (!ciphertext.every(v => /^\d+$/.test(v))) {
                throw new Error("Bản mã RSA phải gồm các số cách nhau bởi dấu cách!");
            }

            if (ciphertext.some(v => BigInt(v) >= keys.n)) {
                throw new Error("Bản mã chứa giá trị >= n, sai khóa hoặc sai bản mã!");
            }

            result = rsaDecryptText(
                ciphertext,
                keys.d,
                keys.n
            );
        }
    }
    else {
        throw new Error(
            "Loại mã hóa không hợp lệ!"
        );
    }
    if (decrypt) {
        plainText.value = result;
    } else {
        cipherText.value = result;
    }
}
encryptBtn.addEventListener(
    "click",
    () => {
        try {
            processCipher(false);
        } catch (error) {
            alert(error.message);
        }
    }
);

decryptBtn.addEventListener(
    "click",
    () => {
        try {
            processCipher(true);
        } catch (error) {
            alert(error.message);
        }
    }
);

updateKeyInput();

// ===============================
// CHỌN NHÓM MÃ HÓA
// ===============================

const cipherGroup = document.getElementById("cipherGroup");

// Danh sách thuật toán theo từng nhóm
const cipherOptions = {

    classical: [
        { value: "caesar", text: "Dịch vòng" },
        { value: "substitution", text: "Mã thay thế" },
        { value: "vigenere", text: "Mã Vigenere" },
        { value: "affine", text: "Mã Affine" },
        { value: "hill", text: "Mã Hill" }
    ],

    modern: [
        { value: "des", text: "DES" },
        { value: "aes", text: "AES" }
    ],

    public: [
        { value: "rsa", text: "RSA" }
    ],

    hash: [
        { value: "md5", text: "MD5" },
        { value: "sha", text: "SHA" }
    ]

};

// Thay đổi danh sách thuật toán
function updateCipherOptions() {

    const group = cipherGroup.value;

    // Xóa danh sách cũ
    cipherType.innerHTML = "";

    // Lấy danh sách mới
    cipherOptions[group].forEach(option => {

        const optionElement = document.createElement("option");

        optionElement.value = option.value;
        optionElement.textContent = option.text;

        cipherType.appendChild(optionElement);

    });
    updateKeyInput();

}

// Khi người dùng thay đổi loại mã hóa
cipherGroup.addEventListener("change", updateCipherOptions);

// Khởi tạo danh sách ban đầu
updateCipherOptions();