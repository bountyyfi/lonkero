// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Build Script for Rust N-API Module
 * Compiles Rust code to .node binary for Node.js
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

extern crate napi_build;

fn main() {
    napi_build::setup();
}
