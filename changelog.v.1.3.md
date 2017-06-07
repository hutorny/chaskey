## chaskey change log v.1.3

`FIX` removed deprecated throw(error) in tests/main.cpp FIX made ror and rol consistent<br>
`FIX` memcmp replaced with time-constant details::equals<br>
`MOD` added extra permute() to improve resistance against related-key attack<br>
`ADD` chaskey::Cipher8s with non-inlined methods to save space<br>
`MOD` adjusted tests on AVR to fit ROM on ATmega256...<br>
