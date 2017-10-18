//
//  SHATests.swift
//  SHATests
//
//  Created by Kenneth Durbrow on 10/17/17.
//  Copyright © 2017 Kenneth M. Durbrow. All rights reserved.
//

import XCTest
@testable import SHA

class SHATests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testEmpty() {
        XCTAssert(SHA1.hash(string: "") == "2jmj7l5rSw0yVb/vlWAYkK/YBwk=")
    }

    func testExample1() {
        XCTAssert(SHA1.hash(string: "The quick brown fox jumps over the lazy dog") == "L9ThxnotKPzthJ7hu3bnORuT6xI=")
    }

    func testExample2() {
        XCTAssert(SHA1.hash(string: "The quick brown fox jumps over the lazy cog") == "3p8sf9JeGzr60+haC9F9mxANtLM=")
    }

    func testPerformance() {
        let b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()_+-=[]{};:'\"\\|/?><,."
        let s = (0..<4096).reduce("") { prv, _ in
            let i = b.index(b.startIndex, offsetBy: Int(arc4random_uniform(UInt32(b.count))))
            return prv + b[i].description
        }
        self.measure {
            for _ in 0..<1000 { _ = SHA1.hash(string: s) }
        }
    }
}
