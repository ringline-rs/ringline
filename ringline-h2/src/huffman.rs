//! Huffman codec for HPACK (RFC 7541 Appendix B).
//!
//! HPACK uses the same static Huffman table defined in RFC 7541. This module
//! provides both encoder and decoder.

use std::sync::OnceLock;

use crate::error::H2Error;

/// Huffman code entry: (code, bit_length).
#[derive(Clone, Copy)]
struct HuffmanCode {
    code: u32,
    bits: u8,
}

/// Huffman encoding table (RFC 7541 Appendix B).
/// Index is the byte value (0-255), plus EOS at 256.
static HUFFMAN_TABLE: [HuffmanCode; 257] = [
    HuffmanCode {
        code: 0x1ff8,
        bits: 13,
    }, // 0
    HuffmanCode {
        code: 0x7fffd8,
        bits: 23,
    }, // 1
    HuffmanCode {
        code: 0xfffffe2,
        bits: 28,
    }, // 2
    HuffmanCode {
        code: 0xfffffe3,
        bits: 28,
    }, // 3
    HuffmanCode {
        code: 0xfffffe4,
        bits: 28,
    }, // 4
    HuffmanCode {
        code: 0xfffffe5,
        bits: 28,
    }, // 5
    HuffmanCode {
        code: 0xfffffe6,
        bits: 28,
    }, // 6
    HuffmanCode {
        code: 0xfffffe7,
        bits: 28,
    }, // 7
    HuffmanCode {
        code: 0xfffffe8,
        bits: 28,
    }, // 8
    HuffmanCode {
        code: 0xffffea,
        bits: 24,
    }, // 9
    HuffmanCode {
        code: 0x3ffffffc,
        bits: 30,
    }, // 10
    HuffmanCode {
        code: 0xfffffe9,
        bits: 28,
    }, // 11
    HuffmanCode {
        code: 0xfffffea,
        bits: 28,
    }, // 12
    HuffmanCode {
        code: 0x3ffffffd,
        bits: 30,
    }, // 13
    HuffmanCode {
        code: 0xfffffeb,
        bits: 28,
    }, // 14
    HuffmanCode {
        code: 0xfffffec,
        bits: 28,
    }, // 15
    HuffmanCode {
        code: 0xfffffed,
        bits: 28,
    }, // 16
    HuffmanCode {
        code: 0xfffffee,
        bits: 28,
    }, // 17
    HuffmanCode {
        code: 0xfffffef,
        bits: 28,
    }, // 18
    HuffmanCode {
        code: 0xffffff0,
        bits: 28,
    }, // 19
    HuffmanCode {
        code: 0xffffff1,
        bits: 28,
    }, // 20
    HuffmanCode {
        code: 0xffffff2,
        bits: 28,
    }, // 21
    HuffmanCode {
        code: 0x3ffffffe,
        bits: 30,
    }, // 22
    HuffmanCode {
        code: 0xffffff3,
        bits: 28,
    }, // 23
    HuffmanCode {
        code: 0xffffff4,
        bits: 28,
    }, // 24
    HuffmanCode {
        code: 0xffffff5,
        bits: 28,
    }, // 25
    HuffmanCode {
        code: 0xffffff6,
        bits: 28,
    }, // 26
    HuffmanCode {
        code: 0xffffff7,
        bits: 28,
    }, // 27
    HuffmanCode {
        code: 0xffffff8,
        bits: 28,
    }, // 28
    HuffmanCode {
        code: 0xffffff9,
        bits: 28,
    }, // 29
    HuffmanCode {
        code: 0xffffffa,
        bits: 28,
    }, // 30
    HuffmanCode {
        code: 0xffffffb,
        bits: 28,
    }, // 31
    HuffmanCode {
        code: 0x14,
        bits: 6,
    }, // 32 ' '
    HuffmanCode {
        code: 0x3f8,
        bits: 10,
    }, // 33 '!'
    HuffmanCode {
        code: 0x3f9,
        bits: 10,
    }, // 34 '"'
    HuffmanCode {
        code: 0xffa,
        bits: 12,
    }, // 35 '#'
    HuffmanCode {
        code: 0x1ff9,
        bits: 13,
    }, // 36 '$'
    HuffmanCode {
        code: 0x15,
        bits: 6,
    }, // 37 '%'
    HuffmanCode {
        code: 0xf8,
        bits: 8,
    }, // 38 '&'
    HuffmanCode {
        code: 0x7fa,
        bits: 11,
    }, // 39 '\''
    HuffmanCode {
        code: 0x3fa,
        bits: 10,
    }, // 40 '('
    HuffmanCode {
        code: 0x3fb,
        bits: 10,
    }, // 41 ')'
    HuffmanCode {
        code: 0xf9,
        bits: 8,
    }, // 42 '*'
    HuffmanCode {
        code: 0x7fb,
        bits: 11,
    }, // 43 '+'
    HuffmanCode {
        code: 0xfa,
        bits: 8,
    }, // 44 ','
    HuffmanCode {
        code: 0x16,
        bits: 6,
    }, // 45 '-'
    HuffmanCode {
        code: 0x17,
        bits: 6,
    }, // 46 '.'
    HuffmanCode {
        code: 0x18,
        bits: 6,
    }, // 47 '/'
    HuffmanCode { code: 0x0, bits: 5 }, // 48 '0'
    HuffmanCode { code: 0x1, bits: 5 }, // 49 '1'
    HuffmanCode { code: 0x2, bits: 5 }, // 50 '2'
    HuffmanCode {
        code: 0x19,
        bits: 6,
    }, // 51 '3'
    HuffmanCode {
        code: 0x1a,
        bits: 6,
    }, // 52 '4'
    HuffmanCode {
        code: 0x1b,
        bits: 6,
    }, // 53 '5'
    HuffmanCode {
        code: 0x1c,
        bits: 6,
    }, // 54 '6'
    HuffmanCode {
        code: 0x1d,
        bits: 6,
    }, // 55 '7'
    HuffmanCode {
        code: 0x1e,
        bits: 6,
    }, // 56 '8'
    HuffmanCode {
        code: 0x1f,
        bits: 6,
    }, // 57 '9'
    HuffmanCode {
        code: 0x5c,
        bits: 7,
    }, // 58 ':'
    HuffmanCode {
        code: 0xfb,
        bits: 8,
    }, // 59 ';'
    HuffmanCode {
        code: 0x7ffc,
        bits: 15,
    }, // 60 '<'
    HuffmanCode {
        code: 0x20,
        bits: 6,
    }, // 61 '='
    HuffmanCode {
        code: 0xffb,
        bits: 12,
    }, // 62 '>'
    HuffmanCode {
        code: 0x3fc,
        bits: 10,
    }, // 63 '?'
    HuffmanCode {
        code: 0x1ffa,
        bits: 13,
    }, // 64 '@'
    HuffmanCode {
        code: 0x21,
        bits: 6,
    }, // 65 'A'
    HuffmanCode {
        code: 0x5d,
        bits: 7,
    }, // 66 'B'
    HuffmanCode {
        code: 0x5e,
        bits: 7,
    }, // 67 'C'
    HuffmanCode {
        code: 0x5f,
        bits: 7,
    }, // 68 'D'
    HuffmanCode {
        code: 0x60,
        bits: 7,
    }, // 69 'E'
    HuffmanCode {
        code: 0x61,
        bits: 7,
    }, // 70 'F'
    HuffmanCode {
        code: 0x62,
        bits: 7,
    }, // 71 'G'
    HuffmanCode {
        code: 0x63,
        bits: 7,
    }, // 72 'H'
    HuffmanCode {
        code: 0x64,
        bits: 7,
    }, // 73 'I'
    HuffmanCode {
        code: 0x65,
        bits: 7,
    }, // 74 'J'
    HuffmanCode {
        code: 0x66,
        bits: 7,
    }, // 75 'K'
    HuffmanCode {
        code: 0x67,
        bits: 7,
    }, // 76 'L'
    HuffmanCode {
        code: 0x68,
        bits: 7,
    }, // 77 'M'
    HuffmanCode {
        code: 0x69,
        bits: 7,
    }, // 78 'N'
    HuffmanCode {
        code: 0x6a,
        bits: 7,
    }, // 79 'O'
    HuffmanCode {
        code: 0x6b,
        bits: 7,
    }, // 80 'P'
    HuffmanCode {
        code: 0x6c,
        bits: 7,
    }, // 81 'Q'
    HuffmanCode {
        code: 0x6d,
        bits: 7,
    }, // 82 'R'
    HuffmanCode {
        code: 0x6e,
        bits: 7,
    }, // 83 'S'
    HuffmanCode {
        code: 0x6f,
        bits: 7,
    }, // 84 'T'
    HuffmanCode {
        code: 0x70,
        bits: 7,
    }, // 85 'U'
    HuffmanCode {
        code: 0x71,
        bits: 7,
    }, // 86 'V'
    HuffmanCode {
        code: 0x72,
        bits: 7,
    }, // 87 'W'
    HuffmanCode {
        code: 0xfc,
        bits: 8,
    }, // 88 'X'
    HuffmanCode {
        code: 0x73,
        bits: 7,
    }, // 89 'Y'
    HuffmanCode {
        code: 0xfd,
        bits: 8,
    }, // 90 'Z'
    HuffmanCode {
        code: 0x1ffb,
        bits: 13,
    }, // 91 '['
    HuffmanCode {
        code: 0x7fff0,
        bits: 19,
    }, // 92 '\\'
    HuffmanCode {
        code: 0x1ffc,
        bits: 13,
    }, // 93 ']'
    HuffmanCode {
        code: 0x3ffc,
        bits: 14,
    }, // 94 '^'
    HuffmanCode {
        code: 0x22,
        bits: 6,
    }, // 95 '_'
    HuffmanCode {
        code: 0x7ffd,
        bits: 15,
    }, // 96 '`'
    HuffmanCode { code: 0x3, bits: 5 }, // 97 'a'
    HuffmanCode {
        code: 0x23,
        bits: 6,
    }, // 98 'b'
    HuffmanCode { code: 0x4, bits: 5 }, // 99 'c'
    HuffmanCode {
        code: 0x24,
        bits: 6,
    }, // 100 'd'
    HuffmanCode { code: 0x5, bits: 5 }, // 101 'e'
    HuffmanCode {
        code: 0x25,
        bits: 6,
    }, // 102 'f'
    HuffmanCode {
        code: 0x26,
        bits: 6,
    }, // 103 'g'
    HuffmanCode {
        code: 0x27,
        bits: 6,
    }, // 104 'h'
    HuffmanCode { code: 0x6, bits: 5 }, // 105 'i'
    HuffmanCode {
        code: 0x74,
        bits: 7,
    }, // 106 'j'
    HuffmanCode {
        code: 0x75,
        bits: 7,
    }, // 107 'k'
    HuffmanCode {
        code: 0x28,
        bits: 6,
    }, // 108 'l'
    HuffmanCode {
        code: 0x29,
        bits: 6,
    }, // 109 'm'
    HuffmanCode {
        code: 0x2a,
        bits: 6,
    }, // 110 'n'
    HuffmanCode { code: 0x7, bits: 5 }, // 111 'o'
    HuffmanCode {
        code: 0x2b,
        bits: 6,
    }, // 112 'p'
    HuffmanCode {
        code: 0x76,
        bits: 7,
    }, // 113 'q'
    HuffmanCode {
        code: 0x2c,
        bits: 6,
    }, // 114 'r'
    HuffmanCode { code: 0x8, bits: 5 }, // 115 's'
    HuffmanCode { code: 0x9, bits: 5 }, // 116 't'
    HuffmanCode {
        code: 0x2d,
        bits: 6,
    }, // 117 'u'
    HuffmanCode {
        code: 0x77,
        bits: 7,
    }, // 118 'v'
    HuffmanCode {
        code: 0x78,
        bits: 7,
    }, // 119 'w'
    HuffmanCode {
        code: 0x79,
        bits: 7,
    }, // 120 'x'
    HuffmanCode {
        code: 0x7a,
        bits: 7,
    }, // 121 'y'
    HuffmanCode {
        code: 0x7b,
        bits: 7,
    }, // 122 'z'
    HuffmanCode {
        code: 0x7ffe,
        bits: 15,
    }, // 123 '{'
    HuffmanCode {
        code: 0x7fc,
        bits: 11,
    }, // 124 '|'
    HuffmanCode {
        code: 0x3ffd,
        bits: 14,
    }, // 125 '}'
    HuffmanCode {
        code: 0x1ffd,
        bits: 13,
    }, // 126 '~'
    HuffmanCode {
        code: 0xffffffc,
        bits: 28,
    }, // 127
    HuffmanCode {
        code: 0xfffe6,
        bits: 20,
    }, // 128
    HuffmanCode {
        code: 0x3fffd2,
        bits: 22,
    }, // 129
    HuffmanCode {
        code: 0xfffe7,
        bits: 20,
    }, // 130
    HuffmanCode {
        code: 0xfffe8,
        bits: 20,
    }, // 131
    HuffmanCode {
        code: 0x3fffd3,
        bits: 22,
    }, // 132
    HuffmanCode {
        code: 0x3fffd4,
        bits: 22,
    }, // 133
    HuffmanCode {
        code: 0x3fffd5,
        bits: 22,
    }, // 134
    HuffmanCode {
        code: 0x7fffd9,
        bits: 23,
    }, // 135
    HuffmanCode {
        code: 0x3fffd6,
        bits: 22,
    }, // 136
    HuffmanCode {
        code: 0x7fffda,
        bits: 23,
    }, // 137
    HuffmanCode {
        code: 0x7fffdb,
        bits: 23,
    }, // 138
    HuffmanCode {
        code: 0x7fffdc,
        bits: 23,
    }, // 139
    HuffmanCode {
        code: 0x7fffdd,
        bits: 23,
    }, // 140
    HuffmanCode {
        code: 0x7fffde,
        bits: 23,
    }, // 141
    HuffmanCode {
        code: 0xffffeb,
        bits: 24,
    }, // 142
    HuffmanCode {
        code: 0x7fffdf,
        bits: 23,
    }, // 143
    HuffmanCode {
        code: 0xffffec,
        bits: 24,
    }, // 144
    HuffmanCode {
        code: 0xffffed,
        bits: 24,
    }, // 145
    HuffmanCode {
        code: 0x3fffd7,
        bits: 22,
    }, // 146
    HuffmanCode {
        code: 0x7fffe0,
        bits: 23,
    }, // 147
    HuffmanCode {
        code: 0xffffee,
        bits: 24,
    }, // 148
    HuffmanCode {
        code: 0x7fffe1,
        bits: 23,
    }, // 149
    HuffmanCode {
        code: 0x7fffe2,
        bits: 23,
    }, // 150
    HuffmanCode {
        code: 0x7fffe3,
        bits: 23,
    }, // 151
    HuffmanCode {
        code: 0x7fffe4,
        bits: 23,
    }, // 152
    HuffmanCode {
        code: 0x1fffdc,
        bits: 21,
    }, // 153
    HuffmanCode {
        code: 0x3fffd8,
        bits: 22,
    }, // 154
    HuffmanCode {
        code: 0x7fffe5,
        bits: 23,
    }, // 155
    HuffmanCode {
        code: 0x3fffd9,
        bits: 22,
    }, // 156
    HuffmanCode {
        code: 0x7fffe6,
        bits: 23,
    }, // 157
    HuffmanCode {
        code: 0x7fffe7,
        bits: 23,
    }, // 158
    HuffmanCode {
        code: 0xffffef,
        bits: 24,
    }, // 159
    HuffmanCode {
        code: 0x3fffda,
        bits: 22,
    }, // 160
    HuffmanCode {
        code: 0x1fffdd,
        bits: 21,
    }, // 161
    HuffmanCode {
        code: 0xfffe9,
        bits: 20,
    }, // 162
    HuffmanCode {
        code: 0x3fffdb,
        bits: 22,
    }, // 163
    HuffmanCode {
        code: 0x3fffdc,
        bits: 22,
    }, // 164
    HuffmanCode {
        code: 0x7fffe8,
        bits: 23,
    }, // 165
    HuffmanCode {
        code: 0x7fffe9,
        bits: 23,
    }, // 166
    HuffmanCode {
        code: 0x1fffde,
        bits: 21,
    }, // 167
    HuffmanCode {
        code: 0x7fffea,
        bits: 23,
    }, // 168
    HuffmanCode {
        code: 0x3fffdd,
        bits: 22,
    }, // 169
    HuffmanCode {
        code: 0x3fffde,
        bits: 22,
    }, // 170
    HuffmanCode {
        code: 0xfffff0,
        bits: 24,
    }, // 171
    HuffmanCode {
        code: 0x1fffdf,
        bits: 21,
    }, // 172
    HuffmanCode {
        code: 0x3fffdf,
        bits: 22,
    }, // 173
    HuffmanCode {
        code: 0x7fffeb,
        bits: 23,
    }, // 174
    HuffmanCode {
        code: 0x7fffec,
        bits: 23,
    }, // 175
    HuffmanCode {
        code: 0x1fffe0,
        bits: 21,
    }, // 176
    HuffmanCode {
        code: 0x1fffe1,
        bits: 21,
    }, // 177
    HuffmanCode {
        code: 0x3fffe0,
        bits: 22,
    }, // 178
    HuffmanCode {
        code: 0x1fffe2,
        bits: 21,
    }, // 179
    HuffmanCode {
        code: 0x7fffed,
        bits: 23,
    }, // 180
    HuffmanCode {
        code: 0x3fffe1,
        bits: 22,
    }, // 181
    HuffmanCode {
        code: 0x7fffee,
        bits: 23,
    }, // 182
    HuffmanCode {
        code: 0x7fffef,
        bits: 23,
    }, // 183
    HuffmanCode {
        code: 0xfffea,
        bits: 20,
    }, // 184
    HuffmanCode {
        code: 0x3fffe2,
        bits: 22,
    }, // 185
    HuffmanCode {
        code: 0x3fffe3,
        bits: 22,
    }, // 186
    HuffmanCode {
        code: 0x3fffe4,
        bits: 22,
    }, // 187
    HuffmanCode {
        code: 0x7ffff0,
        bits: 23,
    }, // 188
    HuffmanCode {
        code: 0x3fffe5,
        bits: 22,
    }, // 189
    HuffmanCode {
        code: 0x3fffe6,
        bits: 22,
    }, // 190
    HuffmanCode {
        code: 0x7ffff1,
        bits: 23,
    }, // 191
    HuffmanCode {
        code: 0x3ffffe0,
        bits: 26,
    }, // 192
    HuffmanCode {
        code: 0x3ffffe1,
        bits: 26,
    }, // 193
    HuffmanCode {
        code: 0xfffeb,
        bits: 20,
    }, // 194
    HuffmanCode {
        code: 0x7fff1,
        bits: 19,
    }, // 195
    HuffmanCode {
        code: 0x3fffe7,
        bits: 22,
    }, // 196
    HuffmanCode {
        code: 0x7ffff2,
        bits: 23,
    }, // 197
    HuffmanCode {
        code: 0x3fffe8,
        bits: 22,
    }, // 198
    HuffmanCode {
        code: 0x1ffffec,
        bits: 25,
    }, // 199
    HuffmanCode {
        code: 0x3ffffe2,
        bits: 26,
    }, // 200
    HuffmanCode {
        code: 0x3ffffe3,
        bits: 26,
    }, // 201
    HuffmanCode {
        code: 0x3ffffe4,
        bits: 26,
    }, // 202
    HuffmanCode {
        code: 0x7ffffde,
        bits: 27,
    }, // 203
    HuffmanCode {
        code: 0x7ffffdf,
        bits: 27,
    }, // 204
    HuffmanCode {
        code: 0x3ffffe5,
        bits: 26,
    }, // 205
    HuffmanCode {
        code: 0xfffff1,
        bits: 24,
    }, // 206
    HuffmanCode {
        code: 0x1ffffed,
        bits: 25,
    }, // 207
    HuffmanCode {
        code: 0x7fff2,
        bits: 19,
    }, // 208
    HuffmanCode {
        code: 0x1fffe3,
        bits: 21,
    }, // 209
    HuffmanCode {
        code: 0x3ffffe6,
        bits: 26,
    }, // 210
    HuffmanCode {
        code: 0x7ffffe0,
        bits: 27,
    }, // 211
    HuffmanCode {
        code: 0x7ffffe1,
        bits: 27,
    }, // 212
    HuffmanCode {
        code: 0x3ffffe7,
        bits: 26,
    }, // 213
    HuffmanCode {
        code: 0x7ffffe2,
        bits: 27,
    }, // 214
    HuffmanCode {
        code: 0xfffff2,
        bits: 24,
    }, // 215
    HuffmanCode {
        code: 0x1fffe4,
        bits: 21,
    }, // 216
    HuffmanCode {
        code: 0x1fffe5,
        bits: 21,
    }, // 217
    HuffmanCode {
        code: 0x3ffffe8,
        bits: 26,
    }, // 218
    HuffmanCode {
        code: 0x3ffffe9,
        bits: 26,
    }, // 219
    HuffmanCode {
        code: 0xffffffd,
        bits: 28,
    }, // 220
    HuffmanCode {
        code: 0x7ffffe3,
        bits: 27,
    }, // 221
    HuffmanCode {
        code: 0x7ffffe4,
        bits: 27,
    }, // 222
    HuffmanCode {
        code: 0x7ffffe5,
        bits: 27,
    }, // 223
    HuffmanCode {
        code: 0xfffec,
        bits: 20,
    }, // 224
    HuffmanCode {
        code: 0xfffff3,
        bits: 24,
    }, // 225
    HuffmanCode {
        code: 0xfffed,
        bits: 20,
    }, // 226
    HuffmanCode {
        code: 0x1fffe6,
        bits: 21,
    }, // 227
    HuffmanCode {
        code: 0x3fffe9,
        bits: 22,
    }, // 228
    HuffmanCode {
        code: 0x1fffe7,
        bits: 21,
    }, // 229
    HuffmanCode {
        code: 0x1fffe8,
        bits: 21,
    }, // 230
    HuffmanCode {
        code: 0x7ffff3,
        bits: 23,
    }, // 231
    HuffmanCode {
        code: 0x3fffea,
        bits: 22,
    }, // 232
    HuffmanCode {
        code: 0x3fffeb,
        bits: 22,
    }, // 233
    HuffmanCode {
        code: 0x1ffffee,
        bits: 25,
    }, // 234
    HuffmanCode {
        code: 0x1ffffef,
        bits: 25,
    }, // 235
    HuffmanCode {
        code: 0xfffff4,
        bits: 24,
    }, // 236
    HuffmanCode {
        code: 0xfffff5,
        bits: 24,
    }, // 237
    HuffmanCode {
        code: 0x3ffffea,
        bits: 26,
    }, // 238
    HuffmanCode {
        code: 0x7ffff4,
        bits: 23,
    }, // 239
    HuffmanCode {
        code: 0x3ffffeb,
        bits: 26,
    }, // 240
    HuffmanCode {
        code: 0x7ffffe6,
        bits: 27,
    }, // 241
    HuffmanCode {
        code: 0x3ffffec,
        bits: 26,
    }, // 242
    HuffmanCode {
        code: 0x3ffffed,
        bits: 26,
    }, // 243
    HuffmanCode {
        code: 0x7ffffe7,
        bits: 27,
    }, // 244
    HuffmanCode {
        code: 0x7ffffe8,
        bits: 27,
    }, // 245
    HuffmanCode {
        code: 0x7ffffe9,
        bits: 27,
    }, // 246
    HuffmanCode {
        code: 0x7ffffea,
        bits: 27,
    }, // 247
    HuffmanCode {
        code: 0x7ffffeb,
        bits: 27,
    }, // 248
    HuffmanCode {
        code: 0xffffffe,
        bits: 28,
    }, // 249
    HuffmanCode {
        code: 0x7ffffec,
        bits: 27,
    }, // 250
    HuffmanCode {
        code: 0x7ffffed,
        bits: 27,
    }, // 251
    HuffmanCode {
        code: 0x7ffffee,
        bits: 27,
    }, // 252
    HuffmanCode {
        code: 0x7ffffef,
        bits: 27,
    }, // 253
    HuffmanCode {
        code: 0x7fffff0,
        bits: 27,
    }, // 254
    HuffmanCode {
        code: 0x3ffffee,
        bits: 26,
    }, // 255
    HuffmanCode {
        code: 0x3fffffff,
        bits: 30,
    }, // 256 EOS
];

// -- Decode tree --

#[derive(Clone, Copy)]
enum Node {
    Internal { left: u16, right: u16 },
    Leaf { sym: u16 },
}

fn decode_tree() -> &'static [Node] {
    static TREE: OnceLock<Vec<Node>> = OnceLock::new();
    TREE.get_or_init(build_decode_tree)
}

fn build_decode_tree() -> Vec<Node> {
    let mut nodes = Vec::with_capacity(1024);
    nodes.push(Node::Internal { left: 0, right: 0 });

    for (sym, entry) in HUFFMAN_TABLE.iter().enumerate() {
        let mut node_idx = 0usize;

        for bit_pos in (0..entry.bits).rev() {
            let bit = (entry.code >> bit_pos) & 1;
            let is_last = bit_pos == 0;

            let (left, right) = match nodes[node_idx] {
                Node::Internal { left, right } => (left, right),
                Node::Leaf { .. } => panic!("Huffman code collision"),
            };

            let child = if bit == 0 { left } else { right };

            if is_last {
                let leaf_idx = nodes.len() as u16;
                nodes.push(Node::Leaf { sym: sym as u16 });
                if bit == 0 {
                    nodes[node_idx] = Node::Internal {
                        left: leaf_idx,
                        right,
                    };
                } else {
                    nodes[node_idx] = Node::Internal {
                        left,
                        right: leaf_idx,
                    };
                }
            } else if child == 0 {
                let new_idx = nodes.len() as u16;
                nodes.push(Node::Internal { left: 0, right: 0 });
                if bit == 0 {
                    nodes[node_idx] = Node::Internal {
                        left: new_idx,
                        right,
                    };
                } else {
                    nodes[node_idx] = Node::Internal {
                        left,
                        right: new_idx,
                    };
                }
                node_idx = new_idx as usize;
            } else {
                node_idx = child as usize;
            }
        }
    }

    nodes
}

// -- Public API --

/// Return the Huffman-encoded length of `data` in bytes.
pub(crate) fn encoded_len(data: &[u8]) -> usize {
    let mut bits = 0usize;
    for &byte in data {
        bits += HUFFMAN_TABLE[byte as usize].bits as usize;
    }
    bits.div_ceil(8)
}

/// Huffman-encode `data` and append to `out`.
pub(crate) fn encode(data: &[u8], out: &mut Vec<u8>) {
    let mut bits: u64 = 0;
    let mut bit_count = 0u8;

    for &byte in data {
        let entry = &HUFFMAN_TABLE[byte as usize];
        bits <<= entry.bits;
        bits |= entry.code as u64;
        bit_count += entry.bits;

        while bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }

    // Pad with EOS prefix (all 1s) to complete the last byte.
    if bit_count > 0 {
        bits <<= 8 - bit_count;
        bits |= (1u64 << (8 - bit_count)) - 1;
        out.push(bits as u8);
    }
}

/// Decode a Huffman-encoded byte slice into plaintext.
pub(crate) fn decode(data: &[u8]) -> Result<Vec<u8>, H2Error> {
    let tree = decode_tree();
    let mut out = Vec::new();

    if data.is_empty() {
        return Ok(out);
    }

    let mut node_idx = 0u16;
    let mut padding_bits = 0u8;

    for (byte_idx, &byte) in data.iter().enumerate() {
        let is_last_byte = byte_idx == data.len() - 1;

        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;

            match tree[node_idx as usize] {
                Node::Internal { left, right } => {
                    node_idx = if bit == 0 { left } else { right };

                    if node_idx == 0 {
                        return Err(H2Error::CompressionError);
                    }

                    if let Node::Leaf { sym } = tree[node_idx as usize] {
                        if sym == 256 {
                            return Err(H2Error::CompressionError);
                        }
                        out.push(sym as u8);
                        node_idx = 0;
                        padding_bits = 0;
                    } else if is_last_byte {
                        padding_bits += 1;
                    }
                }
                Node::Leaf { .. } => unreachable!(),
            }
        }
    }

    // Verify padding: must be at most 7 bits and all 1s (EOS prefix).
    if node_idx != 0 {
        if padding_bits > 7 {
            return Err(H2Error::CompressionError);
        }
        let mut check_node = node_idx;
        for _ in 0..padding_bits {
            match tree[check_node as usize] {
                Node::Internal { right, .. } => {
                    if right == 0 {
                        return Err(H2Error::CompressionError);
                    }
                    check_node = right;
                }
                Node::Leaf { sym } => {
                    if sym != 256 {
                        return Err(H2Error::CompressionError);
                    }
                    break;
                }
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple_strings() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"hello",
            b"www.example.com",
            b"Mon, 21 Oct 2013 20:13:21 GMT",
            b"text/html; charset=utf-8",
        ];

        for &input in test_cases {
            let mut encoded = Vec::new();
            encode(input, &mut encoded);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(
                input,
                decoded.as_slice(),
                "roundtrip failed for {:?}",
                std::str::from_utf8(input)
            );
        }
    }

    #[test]
    fn encoded_len_matches() {
        let data = b"Mon, 21 Oct 2013 20:13:21 GMT";
        let mut encoded = Vec::new();
        encode(data, &mut encoded);
        assert_eq!(encoded_len(data), encoded.len());
    }

    #[test]
    fn all_bytes_roundtrip() {
        let input: Vec<u8> = (0..=255).collect();
        let mut encoded = Vec::new();
        encode(&input, &mut encoded);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(input, decoded);
    }
}
