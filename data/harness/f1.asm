ps_3_0
def c0, 0.5, 0.25, 0.75, 1.0
if_gt c0.x, c0.y
sincos r0.xy, c0.x
endif
mov oC0, r0
