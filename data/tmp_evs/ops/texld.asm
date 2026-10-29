ps_3_0
dcl_texcoord0 v0.xy
dcl_2d s0
def c0, 0.5, 0.25, 0.75, 1.0
def c1, 1.0, 2.0, 3.0, 4.0
def c2, 5.0, 6.0, 7.0, 8.0
mov r0, c0
texld r0, v0, s0
mov oC0, r0
