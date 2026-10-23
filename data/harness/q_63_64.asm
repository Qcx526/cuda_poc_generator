ps_2_0
def c0, 0.5, 0.25, 0.75, 1.0
def c1, 1.0, 2.0, 3.0, 4.0
def c2, 5.0, 6.0, 7.0, 8.0
mov r0, c0
sincos r0.x, c0.x, c63, c64
mov oC0, r0
