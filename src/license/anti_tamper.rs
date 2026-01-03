// Copyright (c) 2026 Bountyy Oy. All rights reserved.

use sha2::{Digest, Sha256, Sha512};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static V_A: AtomicU64 = AtomicU64::new(0);
static V_B: AtomicU64 = AtomicU64::new(0);
static V_C: AtomicU64 = AtomicU64::new(0);
static V_D: AtomicU64 = AtomicU64::new(0);
static V_E: AtomicU64 = AtomicU64::new(0);
static K_0: AtomicU64 = AtomicU64::new(0);
static K_1: AtomicU64 = AtomicU64::new(0);
static K_2: AtomicU64 = AtomicU64::new(0);
static I_A: AtomicUsize = AtomicUsize::new(0);
static I_B: AtomicUsize = AtomicUsize::new(0);
static I_C: AtomicUsize = AtomicUsize::new(0);
static I_D: AtomicUsize = AtomicUsize::new(0);
static T_F: AtomicBool = AtomicBool::new(false);
static K_I: AtomicBool = AtomicBool::new(false);
static C_C: AtomicU64 = AtomicU64::new(0);
static L_T: AtomicU64 = AtomicU64::new(0);
static S_H: AtomicU64 = AtomicU64::new(0);
static R_V: AtomicU64 = AtomicU64::new(0);
static X_0: AtomicU64 = AtomicU64::new(0x8F3A2B1C4D5E6F70);
static X_1: AtomicU64 = AtomicU64::new(0x1A2B3C4D5E6F7A8B);
static X_2: AtomicU64 = AtomicU64::new(0xDEADBEEFCAFEBABE);
static X_3: AtomicU64 = AtomicU64::new(0x0123456789ABCDEF);

const M_A: u64 = 0x426F756E747979_u64;
const M_B: u64 = 0x4C6F6E6B65726F_u64;
const M_C: u64 = 0x536563757265_u64;
const M_D: u64 = 0x50726F74656374_u64;
const M_E: u64 = 0x416E7469_u64;
const M_S: u64 = M_A
    .wrapping_add(M_B)
    .wrapping_add(M_C)
    .wrapping_add(M_D)
    .wrapping_add(M_E);
const P_0: [u8; 16] = [
    0x4C, 0x4F, 0x4E, 0x4B, 0x45, 0x52, 0x4F, 0x2D, 0x55, 0x4E, 0x4C, 0x49, 0x4D, 0x49, 0x54, 0x45,
];
const P_1: [u8; 8] = [0x43, 0x52, 0x41, 0x43, 0x4B, 0x45, 0x44, 0x00];
const P_2: [u8; 8] = [0x4B, 0x45, 0x59, 0x47, 0x45, 0x4E, 0x00, 0x00];
const P_3: [u8; 8] = [0x50, 0x41, 0x54, 0x43, 0x48, 0x45, 0x44, 0x00];
const P_4: [u8; 8] = [0x46, 0x52, 0x45, 0x45, 0x00, 0x00, 0x00, 0x00];

#[inline(never)]
fn g_k() -> u64 {
    let mut h = Sha512::new();
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(&t.to_le_bytes());
    let f1 = g_k as *const () as u64;
    let f2 = v_s as *const () as u64;
    let f3 = s_v as *const () as u64;
    let f4 = i_v as *const () as u64;
    let f5 = f_i as *const () as u64;
    h.update(&f1.to_le_bytes());
    h.update(&f2.to_le_bytes());
    h.update(&f3.to_le_bytes());
    h.update(&f4.to_le_bytes());
    h.update(&f5.to_le_bytes());
    let sv: u64 = 0;
    let sa = &sv as *const u64 as u64;
    h.update(&sa.to_le_bytes());
    h.update(&std::process::id().to_le_bytes());
    let r = h.finalize();
    u64::from_le_bytes(r[0..8].try_into().unwrap())
        ^ u64::from_le_bytes(r[24..32].try_into().unwrap())
}

#[inline(never)]
fn g_k2() -> u64 {
    let mut h = Sha256::new();
    let i = Instant::now();
    let f1 = t_r as *const () as u64;
    let f2 = w_t as *const () as u64;
    h.update(&f1.to_le_bytes());
    h.update(&f2.to_le_bytes());
    h.update(&(i.elapsed().as_nanos() as u64).to_le_bytes());
    let mut hs = DefaultHasher::new();
    std::thread::current().id().hash(&mut hs);
    h.update(&hs.finish().to_le_bytes());
    let r = h.finalize();
    u64::from_le_bytes(r[8..16].try_into().unwrap())
}

#[inline(never)]
fn g_k3() -> u64 {
    let mut v: u64 = 0x123456789ABCDEF0;
    for i in 0..64 {
        v = v.rotate_left(7).wrapping_add(M_A.rotate_right(i as u32));
        v ^= M_B.rotate_left((i * 3) as u32);
    }
    v ^ (std::process::id() as u64).wrapping_mul(0xDEADBEEF)
}

#[inline(never)]
pub fn i_p() -> bool {
    if K_I.load(Ordering::SeqCst) {
        return v_s();
    }
    let k0 = g_k();
    let k1 = g_k2();
    let k2 = g_k3();
    K_0.store(k0, Ordering::SeqCst);
    K_1.store(k1, Ordering::SeqCst);
    K_2.store(k2, Ordering::SeqCst);
    let im = 0xDEAD_BEEF_CAFE_BABEu64;
    V_A.store(im ^ k0, Ordering::SeqCst);
    V_B.store(im ^ k0.rotate_left(13), Ordering::SeqCst);
    V_C.store(im ^ k0.rotate_right(17), Ordering::SeqCst);
    V_D.store(im ^ k1, Ordering::SeqCst);
    V_E.store(im ^ k1.rotate_left(23).wrapping_add(k2), Ordering::SeqCst);
    I_A.store(0, Ordering::SeqCst);
    I_B.store(0, Ordering::SeqCst);
    I_C.store(0, Ordering::SeqCst);
    I_D.store(0, Ordering::SeqCst);
    L_T.store(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        Ordering::SeqCst,
    );
    let sh = c_s_h();
    S_H.store(sh, Ordering::SeqCst);
    K_I.store(true, Ordering::SeqCst);
    v_m()
}

#[inline(never)]
fn c_s_h() -> u64 {
    let mut h = Sha256::new();
    let fns: [*const (); 12] = [
        i_p as *const (),
        s_v as *const (),
        i_v as *const (),
        v_s as *const (),
        v_c as *const (),
        v_f as *const (),
        v_n as *const (),
        f_i as *const (),
        t_r as *const (),
        w_t as *const (),
        c_h as *const (),
        d_d as *const (),
    ];
    for f in fns {
        h.update(&(f as u64).to_le_bytes());
    }
    h.update(&M_A.to_le_bytes());
    h.update(&M_B.to_le_bytes());
    h.update(&M_C.to_le_bytes());
    let r = h.finalize();
    u64::from_le_bytes(r[0..8].try_into().unwrap())
}

#[inline(never)]
fn v_s_h() -> bool {
    let stored = S_H.load(Ordering::SeqCst);
    if stored == 0 {
        return true;
    }
    let current = c_s_h();
    if stored != current {
        t_r("sh");
        return false;
    }
    true
}

#[inline(never)]
pub fn s_v(lh: u64) {
    if T_F.load(Ordering::SeqCst) {
        return;
    }
    let k0 = K_0.load(Ordering::SeqCst);
    let k1 = K_1.load(Ordering::SeqCst);
    let k2 = K_2.load(Ordering::SeqCst);
    if k0 == 0 {
        return;
    }
    let vm = 0x56414C4944_u64 ^ lh;
    V_A.store(vm ^ k0, Ordering::SeqCst);
    V_B.store(vm ^ k0.rotate_left(13), Ordering::SeqCst);
    V_C.store(vm ^ k0.rotate_right(17), Ordering::SeqCst);
    V_D.store(vm ^ k1, Ordering::SeqCst);
    V_E.store(vm ^ k1.rotate_left(23).wrapping_add(k2), Ordering::SeqCst);
    I_A.fetch_add(1, Ordering::SeqCst);
    I_B.fetch_add(1, Ordering::SeqCst);
    I_C.fetch_add(1, Ordering::SeqCst);
    I_D.fetch_add(1, Ordering::SeqCst);
    R_V.store(lh.rotate_left(7) ^ k0.rotate_right(11), Ordering::SeqCst);
    let xv = X_0.load(Ordering::SeqCst) ^ lh;
    X_0.store(xv, Ordering::SeqCst);
    X_1.store(
        X_1.load(Ordering::SeqCst).wrapping_add(lh),
        Ordering::SeqCst,
    );
}

#[inline(never)]
pub fn i_v() -> bool {
    if T_F.load(Ordering::SeqCst) {
        return false;
    }
    let k0 = K_0.load(Ordering::SeqCst);
    let k1 = K_1.load(Ordering::SeqCst);
    let k2 = K_2.load(Ordering::SeqCst);
    if k0 == 0 || !K_I.load(Ordering::SeqCst) {
        return false;
    }
    let sa = V_A.load(Ordering::SeqCst) ^ k0;
    let sb = V_B.load(Ordering::SeqCst) ^ k0.rotate_left(13);
    let sc = V_C.load(Ordering::SeqCst) ^ k0.rotate_right(17);
    let sd = V_D.load(Ordering::SeqCst) ^ k1;
    let se = V_E.load(Ordering::SeqCst) ^ k1.rotate_left(23).wrapping_add(k2);
    if sa != sb || sb != sc || sc != sd || sd != se {
        t_r("sm");
        return false;
    }
    let iv = (sa & 0xFF_FFFF_FFFF) != 0xDEAD_BEEF_CAFE_BABEu64;
    if !v_c() {
        return false;
    }
    if !v_x() {
        return false;
    }
    if iv {
        C_C.fetch_add(1, Ordering::SeqCst);
    }
    iv
}

#[inline(never)]
fn v_s() -> bool {
    let k0 = K_0.load(Ordering::SeqCst);
    if k0 == 0 {
        return false;
    }
    let sa = V_A.load(Ordering::SeqCst) ^ k0;
    let sb = V_B.load(Ordering::SeqCst) ^ k0.rotate_left(13);
    let sc = V_C.load(Ordering::SeqCst) ^ k0.rotate_right(17);
    sa == sb && sb == sc
}

#[inline(never)]
fn v_c() -> bool {
    let a = I_A.load(Ordering::SeqCst);
    let b = I_B.load(Ordering::SeqCst);
    let c = I_C.load(Ordering::SeqCst);
    let d = I_D.load(Ordering::SeqCst);
    if a != b || b != c || c != d {
        t_r("cm");
        return false;
    }
    true
}

#[inline(never)]
fn v_x() -> bool {
    let x0 = X_0.load(Ordering::SeqCst);
    let x1 = X_1.load(Ordering::SeqCst);
    let x2 = X_2.load(Ordering::SeqCst);
    let x3 = X_3.load(Ordering::SeqCst);
    if x2 != 0xDEADBEEFCAFEBABE {
        t_r("x2");
        return false;
    }
    if x3 != 0x0123456789ABCDEF {
        t_r("x3");
        return false;
    }
    let combined = x0 ^ x1;
    if combined == 0 && I_A.load(Ordering::SeqCst) > 0 {
        t_r("xc");
        return false;
    }
    true
}

#[inline(never)]
pub fn v_m() -> bool {
    let sum = M_A
        .wrapping_add(M_B)
        .wrapping_add(M_C)
        .wrapping_add(M_D)
        .wrapping_add(M_E);
    if sum != M_S {
        t_r("mm");
        return false;
    }
    if M_A & 0xFF != 0x79 {
        t_r("ma");
        return false;
    }
    if M_B & 0xFF != 0x6F {
        t_r("mb");
        return false;
    }
    if M_C & 0xFF != 0x65 {
        t_r("mc");
        return false;
    }
    if M_D & 0xFF != 0x74 {
        t_r("md");
        return false;
    }
    if M_A.count_ones() < 20 {
        t_r("mp");
        return false;
    }
    true
}

#[inline(never)]
pub fn v_f() -> bool {
    let fns: [*const (); 8] = [
        i_v as *const (),
        s_v as *const (),
        i_p as *const (),
        t_r as *const (),
        v_m as *const (),
        v_f as *const (),
        f_i as *const (),
        v_n as *const (),
    ];
    for &addr in &fns {
        let a = addr as usize;
        if a == 0 || a == usize::MAX {
            t_r("fp");
            return false;
        }
        if a & 0x3 != 0 {
            t_r("fa");
            return false;
        }
    }
    let min = fns.iter().map(|&p| p as usize).min().unwrap();
    let max = fns.iter().map(|&p| p as usize).max().unwrap();
    if max - min > 32 * 1024 * 1024 {
        t_r("fs");
        return false;
    }
    true
}

#[inline(never)]
pub fn v_n(fp: *const ()) -> bool {
    if fp.is_null() {
        return false;
    }
    let b: &[u8] = unsafe { std::slice::from_raw_parts(fp as *const u8, 32) };
    if b[0] == 0xE9 {
        t_r("jh");
        return false;
    }
    if b[0] == 0xFF && b[1] == 0x25 {
        t_r("ih");
        return false;
    }
    if b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0 {
        t_r("mh");
        return false;
    }
    if b[0] == 0xCC {
        t_r("bp");
        return false;
    }
    if b[0] == 0x90 && b[1] == 0x90 && b[2] == 0x90 {
        t_r("np");
        return false;
    }
    if b[0] == 0xEB {
        t_r("sh");
        return false;
    }
    if b[0] == 0xE8 && b[5] == 0xE9 {
        t_r("ch");
        return false;
    }
    for i in 0..16 {
        if b[i] == 0xCC && b[i + 1] == 0xCC {
            t_r("db");
            return false;
        }
    }
    let mut zeros = 0;
    for i in 0..16 {
        if b[i] == 0x00 {
            zeros += 1;
        }
    }
    if zeros > 8 {
        t_r("zp");
        return false;
    }
    true
}

#[inline(never)]
pub fn d_d() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for l in s.lines() {
                if l.starts_with("TracerPid:") {
                    let p: i32 = l
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if p != 0 {
                        return true;
                    }
                }
            }
        }
        if std::fs::metadata("/proc/self/fd/0")
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            if let Ok(l) = std::fs::read_link("/proc/self/fd/0") {
                let ls = l.to_string_lossy();
                if ls.contains("gdb") || ls.contains("lldb") || ls.contains("strace") {
                    return true;
                }
            }
        }
    }
    let st = Instant::now();
    let mut x: u64 = 0;
    for i in 0..10000 {
        x = x.wrapping_add(i).rotate_left(1);
    }
    std::hint::black_box(x);
    if st.elapsed().as_millis() > 500 {
        return true;
    }
    let st2 = Instant::now();
    std::thread::sleep(std::time::Duration::from_micros(100));
    let el = st2.elapsed().as_micros();
    if el > 50000 {
        return true;
    }
    false
}

#[inline(never)]
fn v_t() -> bool {
    let lt = L_T.load(Ordering::SeqCst);
    if lt == 0 {
        return true;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now < lt {
        t_r("tc");
        return false;
    }
    if now - lt > 86400 * 365 {
        t_r("te");
        return false;
    }
    true
}

#[inline(never)]
fn v_r() -> bool {
    let rv = R_V.load(Ordering::SeqCst);
    let k0 = K_0.load(Ordering::SeqCst);
    if rv == 0 && I_A.load(Ordering::SeqCst) > 0 {
        return true;
    }
    if rv != 0 && k0 != 0 {
        let expected_pattern = rv ^ k0.rotate_right(11);
        if expected_pattern.count_ones() < 5 {
            t_r("rp");
            return false;
        }
    }
    true
}

#[inline(never)]
pub fn b_l() -> bool {
    t_r("hp1");
    false
}

#[inline(never)]
pub fn e_a() {
    t_r("hp2");
}

#[inline(never)]
pub fn d_v() {
    t_r("hp3");
}

#[inline(never)]
pub fn u_l() -> bool {
    t_r("hp4");
    false
}

#[inline(never)]
pub fn s_t() {
    t_r("hp5");
}

#[inline(never)]
pub fn g_f() -> bool {
    t_r("hp6");
    false
}

#[inline(never)]
pub fn p_l(_: &str) -> bool {
    t_r("hp7");
    false
}

#[inline(never)]
pub fn c_h(k: &str) -> bool {
    let kb = k.as_bytes();
    for i in 0..kb.len().min(P_0.len()) {
        if kb.get(i) == P_0.get(i) && i > 10 {
            t_r("hk0");
            return true;
        }
    }
    let kl = k.to_uppercase();
    let patterns = [&P_1[..], &P_2[..], &P_3[..], &P_4[..]];
    for p in patterns {
        let ps: String = p
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        if kl.contains(&ps) {
            t_r("hkp");
            return true;
        }
    }
    if k.len() > 20 && k.chars().filter(|c| *c == '-').count() > 5 {
        let parts: Vec<&str> = k.split('-').collect();
        if parts
            .iter()
            .any(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_uppercase()))
        {
            if parts.len() > 6 {
                t_r("hks");
                return true;
            }
        }
    }
    false
}

#[inline(never)]
pub fn t_r(_r: &str) {
    T_F.store(true, Ordering::SeqCst);
    V_A.store(0, Ordering::SeqCst);
    V_B.store(1, Ordering::SeqCst);
    V_C.store(2, Ordering::SeqCst);
    V_D.store(3, Ordering::SeqCst);
    V_E.store(4, Ordering::SeqCst);
    I_A.store(usize::MAX, Ordering::SeqCst);
    I_B.store(0, Ordering::SeqCst);
    I_C.store(1, Ordering::SeqCst);
    I_D.store(2, Ordering::SeqCst);
    K_0.store(0, Ordering::SeqCst);
    K_1.store(0, Ordering::SeqCst);
    K_2.store(0, Ordering::SeqCst);
    X_0.store(0, Ordering::SeqCst);
    X_1.store(0, Ordering::SeqCst);
    X_2.store(0, Ordering::SeqCst);
    X_3.store(0, Ordering::SeqCst);
    R_V.store(0, Ordering::SeqCst);
    S_H.store(0, Ordering::SeqCst);
}

#[inline(never)]
pub fn w_t() -> bool {
    T_F.load(Ordering::SeqCst)
}

#[inline(never)]
pub fn f_i() -> bool {
    if w_t() {
        return false;
    }
    if !v_m() {
        return false;
    }
    if !v_s() {
        return false;
    }
    if !v_c() {
        return false;
    }
    if !v_f() {
        return false;
    }
    if !v_x() {
        return false;
    }
    if !v_t() {
        return false;
    }
    if !v_r() {
        return false;
    }
    if !v_s_h() {
        return false;
    }
    let crit: [*const (); 6] = [
        i_v as *const (),
        s_v as *const (),
        f_i as *const (),
        t_r as *const (),
        v_m as *const (),
        v_n as *const (),
    ];
    for fp in crit {
        if !v_n(fp) {
            return false;
        }
    }
    if d_d() {
        let cc = C_C.load(Ordering::SeqCst);
        if cc > 10 {
            t_r("dd");
            return false;
        }
    }
    true
}

#[inline(never)]
pub fn q_c() -> bool {
    if w_t() {
        return false;
    }
    if !v_m() {
        return false;
    }
    i_v()
}

#[inline(never)]
pub fn r_c() -> bool {
    let _ = b_l as *const ();
    let _ = e_a as *const ();
    let _ = d_v as *const ();
    let _ = u_l as *const ();
    let _ = s_t as *const ();
    let _ = g_f as *const ();
    let _ = p_l as *const ();
    true
}

#[inline(never)]
pub fn v_a(n: u64) -> u64 {
    let k = K_0.load(Ordering::SeqCst);
    if k == 0 {
        return 0;
    }
    n.wrapping_mul(M_A).wrapping_add(k).rotate_left(13) ^ M_B
}

#[inline(never)]
pub fn c_a(n: u64, e: u64) -> bool {
    let k = K_0.load(Ordering::SeqCst);
    if k == 0 {
        return false;
    }
    let expected = n.wrapping_mul(M_A).wrapping_add(k).rotate_left(13) ^ M_B;
    expected == e
}

pub use b_l as bypass_license_check;
pub use c_h as check_honeypot_key;
pub use d_v as disable_validation;
pub use e_a as enable_all_features;
pub use f_i as full_integrity_check;
pub use i_p as initialize_protection;
pub use i_v as is_validated;
pub use s_v as set_validated;
pub use t_r as trigger_tamper_response;
pub use v_m as verify_magic_constants;
pub use v_n as verify_no_hook;
pub use w_t as was_tampered;
