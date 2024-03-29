{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "bcrypt.c",
                "blake.c",
                "c11.c",
                "fresh.c",
                "fugue.c",
                "groestl.c",
                "hefty1.c",
                "keccak.c",
                "lbry.c",
                "nist5.c",
                "quark.c",
                "qubit.c",
                "scryptjane.c",
                "scryptn.c",
                "sha1.c",
                "sha256d.c",
                "shavite3.c",
                "skein.c",
                "x11.c",
                "x13.c",
                "x15.c",
                "x16r.c",
                "x16rv2.c",
                "sha3/sph_hefty1.c",
                "sha3/sph_fugue.c",
                "sha3/aes_helper.c",
                "sha3/sph_blake.c",
                "sha3/sph_bmw.c",
                "sha3/sph_cubehash.c",
                "sha3/sph_echo.c",
                "sha3/sph_groestl.c",
                "sha3/sph_jh.c",
                "sha3/sph_keccak.c",
                "sha3/sph_luffa.c",
                "sha3/sph_shavite.c",
                "sha3/sph_simd.c",
                "sha3/sph_skein.c",
                "sha3/sph_whirlpool.c",
                "sha3/sph_shabal.c",
                "sha3/sph_ripemd.c",
                "sha3/sph_sha2.c",
                "sha3/sph_sha2big.c",
                "sha3/sph_tiger.c",
                "sha3/hamsi.c",
                "neoscrypt.c",
            ],
            "include_dirs": [
                "crypto",
            ],
            "cflags_cc": [
                "-std=c++0x"
            ],
        }
    ]
}
