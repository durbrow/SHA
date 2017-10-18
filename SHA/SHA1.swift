//
//  SHA1.swift
//  SHA
//
//  Created by Kenneth Durbrow on 10/17/17.
//  Copyright © 2017 Kenneth M. Durbrow. All rights reserved.
//

import Foundation

public class SHA1 {
    private var bytes = 0
    private var H0 : UInt32 = 0x67452301
    private var H1 : UInt32 = 0xEFCDAB89
    private var H2 : UInt32 = 0x98BADCFE
    private var H3 : UInt32 = 0x10325476
    private var H4 : UInt32 = 0xC3D2E1F0
    private let W = UnsafeMutablePointer<UInt32>.allocate(capacity: 16) //[UInt32](repeating: 0, count: 16)
    
    init() {
        W.initialize(to: 0, count: 16)
    }
    deinit {
        W.deallocate(capacity: 16)
    }
}

private func ROL(_ X: UInt32, _ N: Int) -> UInt32 { return (X << N) | (X >> (32 - N)) }

private extension SHA1 {
    func digest() {
        var (a, b, c, d, e) = (H0, H1, H2, H3, H4)
        
        // showRound(0, a, b, c, d, e, 0, 0)
        for i in 0..<20 {
            let w = i < 16 ? W[i] : ROL(W[(i - 16) & 0b1111] ^ W[(i - 14) & 0b1111] ^ W[(i - 8) & 0b1111] ^ W[(i - 3) & 0b1111], 1)
            let fk = 0x5A827999 &+ ((b & c) | (~b & d))
            let t = ROL(a, 5) &+ e &+ w &+ fk
            W[i & 0b1111] = w; e = d; d = c; c = ROL(b, 30); b = a; a = t
            // showRound(i + 1, a, b, c, d, e, i, W[i & 0b1111])
        }
        for i in 20..<40 {
            let w = ROL(W[(i - 16) & 0b1111] ^ W[(i - 14) & 0b1111] ^ W[(i - 8) & 0b1111] ^ W[(i - 3) & 0b1111], 1)
            let fk = 0x6ED9EBA1 &+ (b ^ c ^ d)
            let t = ROL(a, 5) &+ e &+ w &+ fk
            W[i & 0b1111] = w; e = d; d = c; c = ROL(b, 30); b = a; a = t
            // showRound(i + 1, a, b, c, d, e, i, W[i & 0b1111])
        }
        for i in 40..<60 {
            let w = ROL(W[(i - 16) & 0b1111] ^ W[(i - 14) & 0b1111] ^ W[(i - 8) & 0b1111] ^ W[(i - 3) & 0b1111], 1)
            let fk = 0x8F1BBCDC &+ ((b & c) | (b & d) | (c & d))
            let t = ROL(a, 5) &+ e &+ w &+ fk
            W[i & 0b1111] = w; e = d; d = c; c = ROL(b, 30); b = a; a = t
            // showRound(i + 1, a, b, c, d, e, i, W[i & 0b1111])
        }
        for i in 60..<80 {
            let w = ROL(W[(i - 16) & 0b1111] ^ W[(i - 14) & 0b1111] ^ W[(i - 8) & 0b1111] ^ W[(i - 3) & 0b1111], 1)
            let fk = 0xCA62C1D6 &+ (b ^ c ^ d)
            let t = ROL(a, 5) &+ e &+ w &+ fk
            W[i & 0b1111] = w; e = d; d = c; c = ROL(b, 30); b = a; a = t
            // showRound(i + 1, a, b, c, d, e, i, W[i & 0b1111])
        }
        (H0, H1, H2, H3, H4) = (H0 &+ a, H1 &+ b, H2 &+ c, H3 &+ d, H4 &+ e)
    }
    func append(byte: UInt8) {
        let i = (bytes >> 2) & 0b1111
        W[i] = (W[i] << 8) | UInt32(byte)
        bytes += 1
        if bytes & 0b111111 == 0 { ///< digest the morsel (of 512 bits == 64 bytes == 16 words
            digest()
        }
    }
}

public extension SHA1 {
    func append<T>(_ data: T) -> SHA1 where T : Sequence, T.Element == UInt8 {
        var i = (bytes >> 2) & 0b1111
        var acc = W[i]
        for ch in data {
            acc = (acc << 8) | UInt32(ch)
            bytes += 1
            if bytes & 0b11 == 0 {
                W[i] = acc
                i += 1
                acc = 0
                if i == 16 {
                    digest()
                    i = 0
                }
            }
        }
        W[i] = acc
        return self
    }
    func finish() -> Data {
        assert(bytes >= 0)
        let mlen = bytes * 8
        
        append(byte: 0x80) ///< marks the end of the message
        
        // if there isn't 64 bits left then pad with 0's to the start of the next 512-bit morsel
        if bytes & 0b111111 > 56 {
            while bytes & 0b111111 > 56 {
                let i = (bytes >> 2) & 0b1111
                switch bytes & 0x3 {
                case 0:
                    W[i] = 0
                    bytes += 4
                case 1:
                    W[i] <<= 8
                    bytes += 1
                case 2:
                    W[i] <<= 16
                    bytes += 2
                case 3:
                    W[i] <<= 24
                    bytes += 3
                default:
                    assertionFailure("impossible!")
                }
            }
            digest()
        }
        // if there is more than 64 bits left then fill with 0's
        while bytes & 0b111111 < 56 {
            let i = (bytes >> 2) & 0b1111
            switch bytes & 0x3 {
            case 0:
                W[i] = 0
                bytes += 4
            case 1:
                W[i] <<= 8
                bytes += 1
            case 2:
                W[i] <<= 16
                bytes += 2
            case 3:
                W[i] <<= 24
                bytes += 3
            default:
                assertionFailure("impossible!")
            }
        }
        
        // write the message length into the final 64 bits
        W[14] = UInt32(truncatingIfNeeded: mlen >> 32)
        W[15] = UInt32(truncatingIfNeeded: mlen >>  0)
        digest()
        
        var rslt = Data(count: 20)
        rslt[ 0] = UInt8(truncatingIfNeeded: H0 >> 24)
        rslt[ 1] = UInt8(truncatingIfNeeded: H0 >> 16)
        rslt[ 2] = UInt8(truncatingIfNeeded: H0 >>  8)
        rslt[ 3] = UInt8(truncatingIfNeeded: H0 >>  0)
        rslt[ 4] = UInt8(truncatingIfNeeded: H1 >> 24)
        rslt[ 5] = UInt8(truncatingIfNeeded: H1 >> 16)
        rslt[ 6] = UInt8(truncatingIfNeeded: H1 >>  8)
        rslt[ 7] = UInt8(truncatingIfNeeded: H1 >>  0)
        rslt[ 8] = UInt8(truncatingIfNeeded: H2 >> 24)
        rslt[ 9] = UInt8(truncatingIfNeeded: H2 >> 16)
        rslt[10] = UInt8(truncatingIfNeeded: H2 >>  8)
        rslt[11] = UInt8(truncatingIfNeeded: H2 >>  0)
        rslt[12] = UInt8(truncatingIfNeeded: H3 >> 24)
        rslt[13] = UInt8(truncatingIfNeeded: H3 >> 16)
        rslt[14] = UInt8(truncatingIfNeeded: H3 >>  8)
        rslt[15] = UInt8(truncatingIfNeeded: H3 >>  0)
        rslt[16] = UInt8(truncatingIfNeeded: H4 >> 24)
        rslt[17] = UInt8(truncatingIfNeeded: H4 >> 16)
        rslt[18] = UInt8(truncatingIfNeeded: H4 >>  8)
        rslt[19] = UInt8(truncatingIfNeeded: H4 >>  0)
        
        bytes = -1
        return rslt
    }
    static func hash(string: String) -> String {
        return SHA1().append(string.utf8).finish().base64EncodedString()
    }
}
