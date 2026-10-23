ps_3_0
dcl_texcoord0 v0.xy
dcl_2d s0
texld r0, v0, s0
sincos r1.xy, r0.x
mov oC0, r1
