from z3 import *

ADJUST = 0

def check1(userflag):
	sum = 0
	sum += userflag[4] * 0xef7a8c
	sum += 0x9d865d8d
	sum -= userflag[24] * 0x45b53c
	sum += 0x18baee57
	sum -= userflag[0] * 0xe4cf8b
	sum -= 0x913fbbde
	sum -= userflag[8] * 0xf5c990
	sum += 0x6bfaa656
	sum ^= userflag[20] * 0x733178
	sum ^= 0x61e3db3b
	sum ^= userflag[16] * 0x9a17b8
	sum -= 0xca2804b1
	sum ^= userflag[12] * 0x773850
	sum ^= 0x5a6f68be
	sum ^= userflag[28] * 0xe21d3d
	sum ^= 0x5c911d23
	sum += 0x7e9b8586 + 1
	sum &= 0xffffffffffffffff
	return sum

def check2(userflag):
	sum = 0
	sum += userflag[17] * 0x99aa81
	sum -= 0x74edea51
	sum ^= userflag[5] * 0x4aba22
	sum += 0x598015bf
	sum ^= userflag[21] * 0x91a68a
	sum ^= 0x6df18e52
	sum ^= userflag[1] * 0x942fde
	sum += 0x15c825ee
	sum -= userflag[13] * 0xfe2fbe
	sum += 0xd5682b64
	sum -= userflag[29] * 0xd7e52f
	sum += 0x798bd018
	sum ^= userflag[25] * 0xe44f6a
	sum -= 0xe66d523e
	sum += userflag[9] * 0xaf71d6
	sum += 0x921122d3
	sum -= 0xe1148bae
	sum &= 0xffffffffffffffff
	return sum



def check3(userflag):
	sum = 0
	sum += userflag[10] * 0x48c500
	sum -= 0x8fdaa1bc
	sum -= userflag[30] * 0x152887
	sum += 0x65f04e48
	sum -= userflag[14] * 0xaa4247
	sum ^= 0x3d63ec69
	sum ^= userflag[22] * 0x38d82d
	sum ^= 0x872eca8f
	sum ^= userflag[26] * 0xf120ac
	sum += 0x803dbdcf
	sum += userflag[2] * 0x254def
	sum ^= 0xee380db3
	sum ^= userflag[18] * 0x9ef3e7
	sum -= 0x6deaa90b
	sum += userflag[6] * 0x69c573
	sum -= 0xc9ac5c5d
	sum += 0x20c45c0f2 + 1
	sum &= 0xffffffffffffffff
	return sum



def check4(userflag):
	sum = 0
	sum += userflag[11] * 0x67dda4
	sum += 0xf4753afc
	sum += userflag[31] * 0x5bb860
	sum ^= 0xc1d47fc9
	sum ^= userflag[23] * 0xab0ce5
	sum += 0x544ff977
	sum += userflag[7] * 0x148e94
	sum -= 0x9cb3e419
	sum -= userflag[15] * 0x9e06ae
	sum -= 0xadc62064
	sum ^= userflag[3] * 0xfb9de1
	sum ^= 0x4e3633f7
	sum -= userflag[27] * 0xa8a511
	sum ^= 0xa61f9208
	sum += userflag[19] * 0xd3468d
	sum += 0x4a5d7b48
	sum += 0x109bed5d + 1
	sum &= 0xffffffffffffffff
	return sum



def check5(userflag):
	sum = 0
	sum += userflag[12] * 0x640ba9
	sum += 0x516c7a5c
	sum -= userflag[0] * 0xf1d9e5
	sum += 0x8b424d6b
	sum += userflag[28] * 0xd3e2f8
	sum += 0x3802be78
	sum += userflag[24] * 0xb558ce
	sum -= 0x33418c8e
	sum -= userflag[8] * 0x2f03a7
	sum ^= 0xe050b170
	sum += userflag[16] * 0xb8fa61
	sum ^= 0x1fc22df6
	sum -= userflag[20] * 0xe0c507
	sum ^= 0xd8376e57
	sum += userflag[4] * 0x8e354e
	sum -= 0xd2cb3108
	sum -= 0x0e79080 + 0x100000000
	sum &= 0xffffffffffffffff
	return sum



def check6(userflag):
	sum = 0
	sum += userflag[17] * 0xa9b448
	sum ^= 0x9f938499
	sum += userflag[5] * 0x906550
	sum += 0x407021af
	sum ^= userflag[13] * 0xaa5ad2
	sum ^= 0x77cf83a7
	sum ^= userflag[29] * 0xc49349
	sum ^= 0x3067f4e7
	sum += userflag[9] * 0x314f8e
	sum += 0xcd975f3b
	sum ^= userflag[21] * 0x81968b
	sum += 0x893d2e0b
	sum -= userflag[25] * 0x5ffbac
	sum ^= 0xf3378e3a
	sum -= userflag[1] * 0xf63c8e
	sum -= 0x1c1d882b
	sum -= 0x28e5f41 + 0x28BD0554C
	sum &= 0xffffffffffffffff
	return sum



def check7(userflag):
	sum = 0
	sum += userflag[22] * 0xa6edf9
	sum ^= 0x77c58017
	sum -= userflag[18] * 0xe87bf4
	sum -= 0x999bd740
	sum -= userflag[2] * 0x19864d
	sum -= 0x41884bed
	sum += userflag[6] * 0x901524
	sum ^= 0x247bf095
	sum ^= userflag[10] * 0xc897cc
	sum ^= 0xeff7eea8
	sum ^= userflag[14] * 0x731197
	sum += 0x67a0d262
	sum += userflag[30] * 0x5f591c
	sum += 0x316661f9
	sum += userflag[26] * 0x579d0e
	sum -= 0x3427fa1c
	sum -= 0x900d744b
	sum &= 0xffffffffffffffff
	return sum



def check8(userflag):
	sum = 0
	sum += userflag[23] * 0x9afaf6
	sum ^= 0xdb895413
	sum += userflag[19] * 0x7d1a12
	sum -= 0xc679fc44
	sum += userflag[11] * 0x4d84b1
	sum += 0xa30387dc
	sum -= userflag[15] * 0x552b78
	sum ^= 0xf54a725e
	sum ^= userflag[7] * 0xf372a1
	sum -= 0x4c5103ad	
	sum += userflag[31] * 0xb40eb5
	sum ^= 0x16fa70d2
	sum ^= userflag[3] * 0x9e5c18
	sum += 0x38784353
	sum ^= userflag[27] * 0xf2513b
	sum += 0xa1fc09f0
	sum -= 0x102ba + 0x101d5e14e 
	sum &= 0xffffffffffffffff
	return sum



def check9(userflag):
	sum = 0
	sum += userflag[28] * 0xac70b9
	sum += 0xdae0a932
	sum ^= userflag[4] * 0xc42b6f
	sum ^= 0xbc03104c
	sum -= userflag[4] * 0x867193
	sum += 0xdc48c63a
	sum -= userflag[12] * 0x6d31fe
	sum ^= 0x4baeb6d0
	sum -= userflag[16] * 0xaaae58
	sum -= 0xcd7121f8
	sum += userflag[20] * 0x9faa7a
	sum += 0xbe0a2c9c
	sum += userflag[3] * 0x354ac6
	sum ^= 0xd8ad17f1
	sum -= userflag[8] * 0x3f2acb
	sum -= 0x8b6b7d89
	sum -= 0x263f8 + 0x21870D783
	sum &= 0xffffffffffffffff
	return sum



def check10(userflag):
	sum = 0
	sum += userflag[29] * 0xe9d18a
	sum ^= 0xcb5557ea
	sum ^= userflag[25] * 0x8aa5b9
	sum ^= 0x9125a906
	sum -= userflag[17] * 0x241997
	sum += 0x6e46fcb8
	sum += userflag[5] * 0xe3da0f
	sum += 0xaf4428ec
	sum += userflag[13] * 0xa5f9eb
	sum += 0xbde8f9af
	sum += userflag[21] * 0xd6e0fb
	sum -= 0xc9d97243
	sum += userflag[1] * 0x8dc36e
	sum += 0xc54b7d21
	sum ^= userflag[9] * 0xb072ee
	sum -= 0x2a1ab0c1
	sum -= 0x2bf64 + 0x328096d77
	sum &= 0xffffffffffffffff
	return sum



def check11(userflag):
	sum = 0
	sum += userflag[30] * 0xd14f3e
	sum ^= 0xa06c215b
	sum -= userflag[26] * 0xc5ecbf
	sum += 0xb197c5c0
	sum ^= userflag[6] * 0x19ff9c
	sum ^= 0x66e7d06c
	sum += userflag[2] * 0xe3288b
	sum ^= 0x80af4325
	sum ^= userflag[10] * 0xcfb18c
	sum -= 0xe13c8393
	sum ^= userflag[18] * 0xd208e5
	sum += 0xf96d2b51
	sum += userflag[14] * 0x42240f
	sum -= 0x8732273d
	sum -= userflag[22] * 0x1c6098
	sum -= 0xd3d45c5a
	sum -= 0xb3d7e5b
	sum &= 0xffffffffffffffff
	return sum



def check12(userflag):
	sum = 0
	sum += userflag[11] * 0x3768cc
	sum ^= 0x19f61419
	sum -= userflag[3] * 0x43be16
	sum += 0x566cc6a8
	sum ^= userflag[15] * 0xb7cca5
	sum += 0x6db0599e
	sum += userflag[27] * 0xf6419f
	sum ^= 0xbd613538
	sum ^= userflag[19] * 0xae52fc
	sum += 0x717a44dd
	sum -= userflag[23] * 0x5eeb81
	sum += 0xdd02182d
	sum ^= userflag[7] * 0xec1845
	sum ^= 0xef8e5416
	sum += userflag[31] * 0x61a3be
	sum ^= 0x9288d4fa
	sum -= 0x33e + 0x281bdbac7
	sum &= 0xffffffffffffffff
	return sum



def check13(userflag):
	sum = 0
	sum += userflag[16] * 0x336e91
	sum += 0xa1eb20e3
	sum -= userflag[4] * 0xd45de9
	sum -= 0x381ac71a
	sum += userflag[8] * 0x76c8f8
	sum ^= 0xd8caa2cd
	sum -= userflag[20] * 0x945339
	sum += 0x524d7efa
	sum += userflag[12] * 0x4474ec
	sum -= 0xe47e82cd
	sum ^= userflag[0] * 0x51054f
	sum ^= 0x3321c9b1
	sum -= userflag[24] * 0xd7eb3b
	sum += 0x36f6829d
	sum -= userflag[28] * 0xad52e1
	sum ^= 0x6ce2181a
	sum += 0xc64bbbc + 1
	sum &= 0xffffffffffffffff
	return sum



def check14(userflag):
	sum = 0
	sum += userflag[29] * 0x725059
	sum ^= 0xa8b69f6b
	sum += userflag[17] * 0x6dcfe7
	sum ^= 0x653c249a
	sum += userflag[1] * 0x8f4c44
	sum ^= 0x68e87685
	sum -= userflag[9] * 0xd2f4ce
	sum -= 0x87238dc5
	sum ^= userflag[13] * 0xe99d3f
	sum += 0xed16797a
	sum += userflag[5] * 0xada536
	sum -= 0x95a05aa9
	sum -= userflag[25] * 0xe0b352
	sum ^= 0x43c00020
	sum += userflag[21] * 0x8675b6
	sum += 0x34a29213
	sum -= 0x2083 + 0x201949FB
	sum &= 0xffffffffffffffff
	return sum



def check15(userflag):
	sum = 0
	sum += userflag[2] * 0x4a5e95
	sum += 0x5ed7a1f1
	sum += userflag[22] * 0x3a7b49
	sum ^= 0x87a91310
	sum -= userflag[6] * 0xf27038
	sum ^= 0xf64a0f19
	sum += userflag[30] * 0xa187d0
	sum -= 0xbbcc735d
	sum -= userflag[18] * 0xfc991a
	sum ^= 0xf9ddd08f
	sum -= userflag[26] * 0x4e947a
	sum -= 0x59a9172e
	sum ^= userflag[14] * 0x324ead
	sum -= 0x969a7a64
	sum -= userflag[10] * 0x656b1b
	sum += 0x8c112543
	sum += 0x23e24ba38 + 1
	sum &= 0xffffffffffffffff
	return sum



def check16(userflag):
	sum = 0
	sum += userflag[11] * 0x251b86
	sum += 0xa751192c
	sum -= userflag[7] * 0x743927
	sum ^= 0xf851da43
	sum ^= userflag[31] * 0x9a3479
	sum ^= 0x335087a5
	sum ^= userflag[3] * 0x778a0d
	sum ^= 0x4bfd30d3
	sum -= userflag[27] * 0x7e04b5
	sum -= 0x5d540495
	sum ^= userflag[19] * 0xf1c3ee
	sum += 0x460c48a6
	sum += userflag[15] * 0x883b8a
	sum += 0x7b2ffbdc
	sum += userflag[23] * 0x993db1
	sum += 0xa98b28fa
	sum -= 0x2220950 + 0x21FE67384
	sum &= 0xffffffffffffffff
	return sum



def check17(userflag):
	sum = 0
	sum += userflag[2] * 0xbae081
	sum += 0x2359766f
	sum ^= userflag[3] * 0xc2483b
	sum += 0xea986a57
	sum -= userflag[28] * 0x520ee2
	sum ^= 0xa6ff8114
	sum += userflag[1] * 0x9864ba
	sum += 0x42833507
	sum -= userflag[1] * 0x7cd278
	sum ^= 0x360be811
	sum ^= userflag[4] * 0xbe6605
	sum -= 0x4c927a8d
	sum += userflag[20] * 0x3bd2e8
	sum += 0xb790cfd3
	sum -= userflag[12] * 0x548c2b
	sum += 0x2a0e04cc
	sum -= 0x2213319 + 0x22824586f
	sum &= 0xffffffffffffffff
	return sum



def check18(userflag):
	sum = 0
	sum += userflag[17] * 0xfb213b
	sum -= 0x6773d643
	sum ^= userflag[9] * 0xde6876
	sum ^= 0x8649fde3
	sum ^= userflag[29] * 0x629ff7
	sum ^= 0xa0eeb203
	sum -= userflag[25] * 0xdbb107
	sum ^= 0x94aa6b62
	sum -= userflag[1] * 0x262675
	sum -= 0xdfcf5488
	sum += userflag[5] * 0xd691c5
	sum -= 0x5b3ee746
	sum -= userflag[13] * 0xcafc93
	sum -= 0x111bde22
	sum -= userflag[21] * 0x81f945
	sum -= 0x90033b08
	sum += 0x29cb62830 + 1
	sum &= 0xffffffffffffffff
	return sum



def check19(userflag):
	sum = 0
	sum += userflag[10] * 0x52f44d
	sum ^= 0x33b3d0e4
	sum ^= userflag[30] * 0xe6e66e
	sum -= 0x275d79b0
	sum -= userflag[6] * 0xf98017
	sum ^= 0x456e6c1d
	sum -= userflag[14] * 0x34fcb0
	sum ^= 0x28709cd8
	sum ^= userflag[2] * 0x4d8ba9
	sum += 0xb5482f53
	sum ^= userflag[18] * 0x6c7e92
	sum += 0x2af1d741
	sum += userflag[22] * 0xa4711e
	sum ^= 0x22e79af6
	sum += userflag[26] * 0x33d374
	sum -= 0x117efc0e
	sum -= 0x79438e00 + 0x1a35b58e
	sum &= 0xffffffffffffffff
	return sum



def check20(userflag):
	sum = 0
	sum += userflag[27] * 0x65ac37
	sum += 0x15e586b0
	sum ^= userflag[31] * 0xc6dde0
	sum ^= 0x2354cad4
	sum ^= userflag[15] * 0x154abd
	sum ^= 0xfee57fd5
	sum ^= userflag[19] * 0xa5e467
	sum += 0x315624ef
	sum ^= userflag[23] * 0xb6bed6
	sum -= 0x5285b0a5
	sum -= userflag[7] * 0x832ae7
	sum += 0xe961bedd
	sum += userflag[11] * 0xc46330
	sum -= 0x4a9e1d65
	sum ^= userflag[3] * 0x3f8467
	sum ^= 0x95a6a1c4
	sum -= 0x11143 + 0x1110d23d6
	sum &= 0xffffffffffffffff
	return sum



def check21(userflag):
	sum = 0
	sum += userflag[24] * 0xb74a52
	sum ^= 0x8354d4e8
	sum ^= userflag[4] * 0xf22ecd
	sum -= 0x34cbf23b
	sum += userflag[20] * 0xbef4be
	sum ^= 0x60a6c39a
	sum ^= userflag[1] * 0x7fe215
	sum += 0xb14a7317
	sum -= userflag[2] * 0xdb9f48
	sum -= 0xbca905f2
	sum -= userflag[28] * 0xbb4276
	sum -= 0x920e2248
	sum ^= userflag[28] * 0xa3fbef
	sum += 0x4c22d2d3
	sum ^= userflag[12] * 0xc5e883
	sum ^= 0x50a6e5c9
	sum += 0x271a4239 - 0x2bcbc17a
	sum &= 0xffffffffffffffff
	return sum



def check22(userflag):
	sum = 0
	sum += userflag[13] * 0x4b2d02
	sum ^= 0x4b59b93a
	sum -= userflag[9] * 0x84bb2c
	sum ^= 0x42d5652c
	sum ^= userflag[25] * 0x6f2d21
	sum += 0x1020133a
	sum += userflag[29] * 0x5fe38f
	sum -= 0x62807b20

	sum += userflag[21] * 0xea20a5
	sum ^= 0x60779ceb
	sum ^= userflag[17] * 0x5c17aa
	sum ^= 0x1aaf8a2d
	sum -= userflag[5] * 0xb9feb0
	sum -= 0xadbe02fb
	sum -= userflag[1] * 0x782f79
	sum -= 0xcfc12836
	sum += 0x1b77294f9 + 1
	
	sum &= 0xffffffffffffffff
	return sum



def check23(userflag):
	sum = 0
	sum += userflag[6] * 0x608d19
	sum -= 0x2eee62ec
	sum -= userflag[14] * 0xbe18f4
	sum ^= 0xb86f9b72
	sum ^= userflag[30] * 0x88dec9
	sum += 0xaf5cd797
	sum ^= userflag[18] * 0xb68150
	sum -= 0x3d073ba5
	sum += userflag[22] * 0x4d166c
	sum += 0xbb1e1039
	sum -= userflag[2] * 0x495e3f
	sum += 0xe727b98e
	sum -= userflag[10] * 0x5caba1
	sum -= 0x1a3cf6c1
	sum += userflag[26] * 0x183a4d
	sum -= 0xca0397e1
	sum -= 0x6684a31d
	sum &= 0xffffffffffffffff
	return sum



def check24(userflag):
	sum = 0
	sum += userflag[11] * 0xffd0ca
	sum -= 0x8f26cee8
	sum ^= userflag[7] * 0xbf2b59
	sum += 0xc76bad6e
	sum += userflag[23] * 0x29df01
	sum += 0xeef034a2
	sum ^= userflag[27] * 0xbbda1d
	sum += 0x5923194e
	sum -= userflag[31] * 0x5d24a5
	sum -= 0x81100799
	sum += userflag[15] * 0x3dc505
	sum -= 0x69baee91
	sum ^= userflag[19] * 0x4e25a6
	sum += 0x2468b30a
	sum -= userflag[3] * 0xae1920
	sum ^= 0xd3db6142
	sum -= 0x1bc6a - 0xE4486CC5B + 0x1000000000
	sum &= 0xffffffffffffffff
	return sum



def check25(userflag):
	sum = 0
	sum += userflag[4] * 0xf56c62
	sum ^= 0x6c7d1f41
	sum += userflag[16] * 0x615605
	sum += 0x5b52f6ee
	sum += userflag[20] * 0x828456
	sum ^= 0x6f059759
	sum -= userflag[28] * 0x50484b
	sum += 0x84e222af
	sum ^= userflag[1] * 0x89d640
	sum += 0xfd21345b
	sum -= userflag[24] * 0xe4b191
	sum += 0xfe15a789
	sum ^= userflag[24] * 0x8c58c1
	sum ^= 0x4c49009f
	sum += userflag[12] * 0xa13c4c
	sum ^= 0x27c5288e
	sum -= 0x473 + 0x327587918
	sum &= 0xffffffffffffffff
	return sum



def check26(userflag):
	sum = 0
	sum += userflag[1] * 0x73aaf0
	sum ^= 0xa04e34f1
	sum += userflag[29] * 0xf61e43
	sum += 0xd09b66f3
	sum += userflag[25] * 0x8cb5f0
	sum += 0xc11c9b4b
	sum ^= userflag[17] * 0x4f53a8
	sum -= 0x6465672e
	sum += userflag[9] * 0xb2e1fa
	sum ^= 0x77c07fd8
	sum -= userflag[21] * 0xb8b7b3
	sum -= 0x882c1521
	sum += userflag[13] * 0x13b807
	sum ^= 0x758dd142
	sum ^= userflag[5] * 0xdd40c4
	sum -= 0x449786e6
	sum -= 0xb05dd93c + 0x100000000
	sum &= 0xffffffffffffffff
	return sum



def check27(userflag):
	sum = 0
	sum += userflag[14] * 0xca894b
	sum += 0xa34fe406
	sum += userflag[18] * 0x11552b
	sum += 0x3764ecd4
	sum ^= userflag[22] * 0x7dc36b
	sum += 0xb45e777b
	sum ^= userflag[26] * 0xcec5a6
	sum ^= 0x2d59bc15
	sum += userflag[30] * 0xb6e30d
	sum ^= 0xfab9788c
	sum ^= userflag[10] * 0x859c14
	sum += 0x41868e54
	sum += userflag[6] * 0xd178d3
	sum += 0x958b0be3
	sum ^= userflag[2] * 0x61645c
	sum += 0x9dc814cf
	sum -= 0x47b8057 + 0x4770494eb
	sum &= 0xffffffffffffffff
	return sum



def check28(userflag):
	sum = 0
	sum += userflag[27] * 0x7239e9
	sum -= 0x760e5ada
	sum -= userflag[3] * 0xf1c3d1
	sum -= 0xef28a068
	sum ^= userflag[11] * 0x1b1367
	sum ^= 0x31e00d5a
	sum ^= userflag[19] * 0x8038b3
	sum += 0xb5163447
	sum += userflag[31] * 0x65fac9
	sum += 0xe04a889a
	sum -= userflag[23] * 0xd845ca
	sum -= 0xab7d1c58
	sum += userflag[15] * 0xb2bbbc
	sum ^= 0x3a017b92
	sum ^= userflag[7] * 0x33c8bd
	sum += 0x540376e3
	sum += 0x4f17f36c + 1
	sum &= 0xffffffffffffffff
	return sum



def check29(userflag):
	sum = 0
	sum += userflag[7] * 0x53a4e0
	sum -= 0x6061803e
	sum -= userflag[16] * 0x9bbfda
	sum += 0x69b383f1
	sum -= userflag[24] * 0x6b38aa
	sum -= 0x971317a0
	sum += userflag[20] * 0x5d266f
	sum += 0x5a4b0e60
	sum -= userflag[1] * 0xedc3d3
	sum ^= 0x93e59af6
	sum -= userflag[4] * 0xb1f16c
	sum ^= 0xe8d2b9a9
	sum += userflag[12] * 0x1c8e5b
	sum -= 0x68839283
	sum += userflag[28] * 0x78f67b
	sum -= 0xf53dd889
	sum += 0x1b154dda2 - 0xebd3032dc + 0x1000000000
	sum &= 0xffffffffffffffff
	return sum



def check30(userflag):
	sum = 0
	sum += userflag[17] * 0x87184c
	sum -= 0x72a15ad8
	sum ^= userflag[25] * 0xf6372e
	sum += 0x16ad4f89
	sum -= userflag[21] * 0xd7355c
	sum -= 0xbb20fe35
	sum ^= userflag[5] * 0x471dc1
	sum ^= 0x572c95f4
	sum -= userflag[1] * 0x8c4d98
	sum -= 0x94650c74
	sum -= userflag[13] * 0x5ceea1
	sum ^= 0xf703dcc1
	sum -= userflag[29] * 0xeb0863
	sum += 0xad3bc09d
	sum ^= userflag[9] * 0xb6227f
	sum -= 0x46ae6a17
	sum += 0xcea17ee7 + 1
	sum &= 0xffffffffffffffff
	return sum



def check31(userflag):
	sum = 0
	sum += userflag[30] * 0x8c6412
	sum ^= 0xc08c361c
	sum ^= userflag[14] * 0xb253c4
	sum += 0x21bb1147
	sum += userflag[2] * 0x8f0579
	sum -= 0xfa691186
	sum -= userflag[22] * 0x7ac48a
	sum += 0xbb787dd5
	sum += userflag[10] * 0x2737e6
	sum ^= 0xa2bb7683
	sum -= userflag[18] * 0x4363b9
	sum ^= 0x88c45378
	sum ^= userflag[6] * 0xb38449
	sum -= 0x209dc078
	sum += userflag[26] * 0x6e1316
	sum += 0x1343dee9
	sum -= 0xe369bc + 0xe2862b6b
	sum &= 0xffffffffffffffff
	return sum

def check32(userflag):
	sum = 0
	sum += userflag[19] * 0x390b78
	sum += 0x7d5deea4
	sum -= userflag[15] * 0x70e6c8
	sum -= 0x6ea339e2
	sum ^= userflag[27] * 0xd8a292
	sum -= 0x288d6ec5
	sum -= userflag[23] * 0x978c71
	sum -= 0xe5d85ed8
	sum += userflag[31] * 0x9a14d4
	sum -= 0xb69670cc
	sum ^= userflag[7] * 0x995144
	sum -= 0xd2e77342
	sum ^= userflag[11] * 0x811c39
	sum -= 0x2dd03565
	sum ^= userflag[3] * 0x9953d7
	sum ^= 0x80877669
	sum += 0x206bddb87 + 1
	sum &= 0xffffffffffffffff
	return sum

inp = [BitVec(f'inp{i}', 64) for i in range(32)]  

solver = Solver()
set_param("parallel.enable", True)
for i in range(32):
    solver.add(inp[i] >= 0x24)
    solver.add(inp[i] <= 0x7a)



solver.add(check1(inp) == 0)
solver.add(check2(inp) == 0)
solver.add(check3(inp) == 0)
solver.add(check4(inp)  == 0) 
solver.add(check5(inp) == 0)
solver.add(check6(inp) == 0)
solver.add(check7(inp) == 0)
solver.add(check8(inp) == 0)
solver.add(check9(inp) == 0)
solver.add(check10(inp) == 0)
solver.add(check11(inp) == 0)
solver.add(check12(inp) == 0)
solver.add(check13(inp) == 0) 
solver.add(check14(inp) == 0)
solver.add(check15(inp) == 0) 
solver.add(check16(inp) == 0) 
solver.add(check17(inp) == 0)
solver.add(check18(inp) == 0) 
solver.add(check19(inp) == 0) 
solver.add(check20(inp) == 0) 
solver.add(check21(inp) == 0)
solver.add(check22(inp) == 0) 
solver.add(check23(inp) == 0)
solver.add(check24(inp) == 0) 
solver.add(check25(inp) == 0)
solver.add(check26(inp) == 0) 
solver.add(check27(inp) == 0) 
solver.add(check28(inp) == 0) 
solver.add(check29(inp) == 0)
solver.add(check30(inp) == 0) 
solver.add(check31(inp) == 0) 
solver.add(check32(inp) == 0)


set_param("parallel.enable", True)
while solver.check() == sat:
	model = solver.model()
	solution = []
	for i in range(32):
		solution.append(chr(model[inp[i]].as_long()))
	valstr = ''.join(solution).encode()
	print("Solution found:", valstr)