---
title: "CSAW22 - Attacking a Linear PRNG with LLL"
date: 2022-11-15T18:37:48+05:30
draft: false
math: true
---

This is a writeup of the cryptography task "Master of PRNG" from the CSAW finals 2022. It had around 6 solves by the end of the CTF.

The first part of this challenge involves generalizing the classic Hidden Number Problem to a case with 2 constants, followed by the usual CVP. The second part additionally involves a simple but subtle observation regarding the public moduli.

The challenge file can be found here: [chall.py](/assets/csaw22/csaw22-prng-chall.py)

## Challenge Summary
Let $n_1, n_2$ be 512 bit prime moduli

$a_1, a_2 \in Z_{n_1}$ and $b_1, b_2 \in Z_{n_2}$ are randomly generated coefficients.

In summary, We have a PRNG scheme seeded with $0 \leq x_0, x_1, y_0, y_1 \leq n_2$ where

$$x_i \equiv a_1x_{i-1} + a_2x_{i-2}\ mod\ n_1$$
$$y_i \equiv b_1y_{i-1} + b_2y_{i-2}\ mod\ n_2$$
$$z_i \equiv x_i - y_i\ mod\ n_1$$

$a_1, a_2, b_1, b_2, n_1, n_2$ are public parameters

We're given $x_i$ && $2^{307}, z_i$ >> $204$ << $204\ |\ 2 \leq i \leq 6$ and need to predict $y_7$ for the flag.

Given $x_i$ and $z_i$, the challenge would be trivial since we could easily recover $y_i\ 2 \leq i \leq 6$ and use it to predict $y_7$. The problem is, the upper 204 bits for x and lower 204 bits for z have been masked out.

Essentially, we're missing the upper ~204 bits for $x_i$ and the lower ~204 bits for $z_i$ ($x_i, z_i$ ~ 512 bits so we're missing around 40% of the bits)

## Solution
Examining, the equations for $x_i$

For $2 \leq i \leq 6$, we have,
$$x_i \equiv a1_ix_{1} + a2_ix_{0}\ mod\ n_1$$
Where $a1_i, a2_i$ can be computed from $a_{1}, a_{2}$

For example,
$$x_2 \equiv a_1x_{1} + a_2x_{0}\ mod\ n_1$$
$$x_3 \equiv a_1x_{2} + a_2x_{1} = (a_1^2 + a_2)x_1 + a_1a_2x_0 \ mod\ n_1$$

This can be re-written as
$$2^{307}ux_i + lx_i \equiv a1_ix_{1} + a2_ix_{0}\ mod\ n_1$$
Where $lx_i$ are the lower 307 bits (known) and $ux_i$ are the remaining upper bits (unknown)

Multiplying by $2^{-307}$, we end up with an equation of the form

$$ux_i + c_i \equiv a1_ix_{1} + a2_ix_{0}\ mod\ n_1$$

We have 5 such equations and wish to recover $ux_{i}$, where $ux_{i}$ is relatively small (0.4 * the bitlength of $n_1$).

On a closer look, this looks really similar to the Hidden Number Problem, used in biased nonce attacks against Elliptic Curves. In HNP, we have a set of m equations 

$$x_i + a_i \equiv t_iy\ mod\ p\ 0 \leq i \leq m$$ where y is an unknown constant and the $x_i$, which we wish to recover are small. The difference is that we have 2 constants ($x_0, x_1$) instead of a single y. To extend HNP to our case, we must understand the intuition behind how it's reduced to lattice CVP.

Let **X** be the vector of $x_i$

**A** be the vector of $a_i$

**T** be the vector of $t_i$

**$P_i$** be a vector with p in the ith index and 0 everywhere else

Our set of equations can be represented in vector form as

**X** + **A** = **T***y - $\sum_{i\ =\ 0}^{n} k_{i}$$P_{i}$

Since y and $k_i$ are all integers, **X** + **A** lies in the lattice $L$ spanned by the basis (**T**, **$P_0$**, **$P_1$** ... **$P_n$**)

Since **X** is small, if we look for the vector in $L$ closest to **A**, we can recover **X** with high probability. There are certain limitations (check minkowski's theorem) but intuitively, this is how it works. Extrapolating from this to our equations

$$ux_i + c_i \equiv a1_ix_{1} + a2_ix_{0}\ mod\ n_1\ = a1_ix_{1} + a2_ix_{0} - k_in_1$$

**X** + **C** = **A1**$x_1$ + **A2**$x_0$ - $\sum_{i\ =\ 0}^{n} k_{i}$$P_{i}$

Where
**X** is the vector of $ux_i$
**C** is the vector of $c_i$
**A1** is the vector of $a1_i$
**A2** is the vector of $a2_i$

so **X** + **A** lies in the lattice
$$L\ =\ \left[\begin{matrix}
n_1 & 0 & 0 & 0 & 0 \newline
0 & n_1 & 0 & 0 & 0 \newline
0 & 0 & n_1 & 0 & 0 \newline
0 & 0 & 0 & n_1 & 0 \newline
0 & 0 & 0 & 0 & n_1 \newline
a1_{2} & a1_{3} & a1_{4} & a1_{5} & a1_{6}\newline
a2_{2} & a2_{3} & a2_{4} & a2_{5} & a2_{6}
\end{matrix}\right]$$

Thus, $$X\ =\ CVP(L, A) - A$$

GG, we have successfully recovered all $x_i$.
Here's the sage code I wrote for this

```python
def solve_cvp_1(B, t):
    t_ = t - B.stack(t).gram_schmidt()[0].row(-1)
    B_ = B.LLL()
    c = B_.solve_left(t_)
    c_ = vector(map(round, c))
    return c_ * B_

coeffsx = [(1, 0), (0, 1)]

for _ in range(5):
    coeffsx.append((coeffsx[-1][0]*a_1 + coeffsx[-2][0]*a_2, coeffsx[-1][1]*a_1 + coeffsx[-2][1]*a_2))

coeffsx = coeffsx[2:]

mat = [[0]*5 for _ in range(7)]
v = [0]*5

sf =  (2 ** 307)
si = Integer(Mod(sf, n1)^-1)
for i in range(5):
    mat[i][i] = n1
    mat[5][i] = si*coeffsx[i][0]
    mat[6][i] = si*coeffsx[i][1]
    v[i] = si*ret_xs[i]

mat = Matrix(ZZ, mat)
v = vector(ZZ, v)
t = solve_cvp(mat, v)

x2 = (sf*(t-v)[0] + ret_xs[0])%n1
x3 = (sf*(t-v)[1] + ret_xs[1])%n1

x_state = [x2, x3]
for i in range(3):
    x_state.append((a_1*x_state[-1] + a_2*x_state[-2])%n1)
```

Now for $z_i$, rewriting the equation for $y_i$ in as similar way as $x_i$, we get

$$z_i \equiv x_i - y_i\ mod\ n_1$$
$$uz_i + lz_i \equiv x_i - (b1_iy_1 + b2_iy_0\ mod\ n_2)\ mod\ n_1$$
$$uz_i + lz_i = x_i - (b1_iy_1 + b2_iy_0\ - k1_in_2)\ - k2_in_1$$

We now know $x_i$ and wish to recover $lz_i$, but the double mod poses a problem. We can't have both $n_1$ and $n_2$ in the lattice basis as they are coprime and would just cancel out any other values, giving a rank 0 basis.

I was stuck on this part for a while. One of the things I noticed was $n_2 < n_1$, meaning $y_0\ mod\ n_1 = y_0, y_1\ mod\ n_1 = y_1$. So I spent a lot of time trying to homogenize the entire equation to $Z_(n_1n_2)$ with CRT but it didn't work out. Then I got hit with the stupidly simple observation that had been staring me in the face in the entire time. 

Given $n_1 > n_2$,
$$x_i = O(n_1), y_i ~ O(n_2) \implies x_i - y_i = O(n_1)$$
Meaning $k2_i$ is small! Infact, practically, $k2_i \in {-1, 0, 1\}$

Let's say we know the values for all $k2_i$ (since we can just bruteforce the $3^5$ possibilities), we end up with the system of equations

$$b1_iy_1 + b2_iy_0 - k1_in_2 = c_i - lz_i$$
where $c_i = x_i - k2_in_1 - uz_i$

So $C - LZ$ lies in the lattice

$$L\ =\ \left[\begin{matrix}
n_2 & 0 & 0 & 0 & 0 \newline
0 & n_2 & 0 & 0 & 0 \newline
0 & 0 & n_2 & 0 & 0 \newline
0 & 0 & 0 & n_2 & 0 \newline
0 & 0 & 0 & 0 & n_2 \newline
b1_{2} & b1_{3} & b1_{4} & b1_{5} & b1_{6}\newline
b2_{2} & b2_{3} & b2_{4} & b2_{5} & b2_{6}
\end{matrix}\right]$$

$$V = \left[c_2 - lz_2\ c_3 - lz_3\ c_4 - lz_4\ c_5 - lz_5\ c_6 - lz_6\ \right]^T \in L$$
$$C - V = LZ$$

Since LZ is small, we have

$$LZ = C - CVP(L, V)$$

Iterating over all $3^5$ possibilities of C (by varying $k2_i \in \{-1, 0, 1\}$) we can identify the correct **LZ** as the one where
all values have the expected bitlength (~205)

```python
xv = vector(ZZ, x_state)

mat = [[0]*5 for _ in range(7)]
v = [0]*5

for i in range(5):
    mat[i][i] = n2
    mat[5][i] = coeffsy[i][0]%n2
    mat[6][i] = coeffsy[i][1]%n2

mat = Matrix(ZZ, mat)

z = [-1, 0, 1]
dels = list(map(lambda x: vector(ZZ, list(x)), list(itertools.product(z, repeat=5))))

for d in dels:
    v = xv - vector(ZZ, ret_zs) - d*n1
    t = solve_cvp(mat, v)
    if max(v - t).nbits() < 250:
        y_state = list(t)
        k = (b_1*y_state[-1] + b_2*y_state[-2])%n2
        print ("y_7 = ", k)
        break
```

`flag{_w0w_y0u_@r3_s0_g00d_@_L4t7ice_}`

## Complete Code

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.modules.free_module_integer import IntegerLattice
import itertools

def solve_cvp(mat, target):
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff

module_bit = 512
beta = 0.6
a_1,a_2 =  [9919754465736816172569173052425931289517829891854342593290927744542118133847348662406222547572947297178727236300405992491684375909305177189047780739423811, 2558159371069956421749072997341298610563190398496109008773995596731281585562821740934514052081914548707643961639133075782257512937408016925625816701379184]
b_1,b_2 =  [2605193676009044327751542404995552395651364785430784591434496675113980641629822868464738894812540539614357309531957125239722030117295601326651054134997855, 3197045230062951998763856325415663842943082118997359612045648551897230423045976716318651375603679498159844171771317291574116847000481449039959441081514627]
n1 =  11681289596798868397030596649789726767285990000843272211957420810019522067387532211264897471096909399295930769738569665286430964000906934541163352714344519
n2 =  10557965421921341302784057525127038885537939006621468287750526343357317493360177624286054901157989185048184920439519551848192429179141349006037985539214071
ret_xs =  [258466590698311071331247037930868824798600351331801120333006455557946900924072178631112955877, 9821442718613283840479818314015332171481079398147839951441986495105073061641539763228587316, 44840961768274714901326962447354283020302651991130253647924461474246517162698016799008370900, 4181026132314144744475531197443398345060712084263169112302700944672100108051705214872237804, 165146543464042899162832236414189105534540273973129205248892886798269176015886688299461120067]
ret_zs =  [11425495409956732054927782736077190158254288269207497569801502736793464884202670506015379318738941018498330797528225268357863433326525610294847934650384384, 6493331726937754866196531134748756985061780536063848814074103775547995272554729994318400024248625477632819500830464284078877134996898279637865644465061888, 993089766452002806192286220960438231942075399393023941745370499613681022868865277955412695258671518735133398965459541404411563617841529593232577007714304, 9947918164778455706315062500056819613968192691484842758450452417155875586535345223342626196771965216296162822961357707526761812463743778564968870859243520, 6798568953150532649740005658966557905457680624368167498216858785007123058363282156005182480229608829437870473084370507240870801760529936705635869020651520]      
encflag =  b'\x84\x0bk\xfbmp\x1aV\x95q\r\x9bZ/s\xe5\xb4\xa5Y~y\xac\xaa\xd1\xff\xf1\xf1\xee#\xbd\x07:n\x9c\xd6\xcdV*\xfc\xbe0\x96\xff\xff\xa1E\xdd\xb3\x96\xa2\xb2\x8cW\xc2#6Y\xa0\xf2\xd7\xb7*\xbb\xfb'
ct = bytes_to_long(encflag)

coeffsx = [(1, 0), (0, 1)]
coeffsy = [(1, 0), (0, 1)]

for _ in range(5):
    coeffsx.append((coeffsx[-1][0]*a_1 + coeffsx[-2][0]*a_2, coeffsx[-1][1]*a_1 + coeffsx[-2][1]*a_2))
    coeffsy.append((coeffsy[-1][0]*b_1 + coeffsy[-2][0]*b_2, coeffsy[-1][1]*b_1 + coeffsy[-2][1]*b_2))

coeffsx = coeffsx[2:]
coeffsy = coeffsy[2:]

mat = [[0]*5 for _ in range(7)]
v = [0]*5

sf =  (2 ** int(module_bit * beta))
si = Integer(Mod(sf, n1)^-1)
for i in range(5):
    mat[i][i] = n1
    mat[5][i] = si*coeffsx[i][0]
    mat[6][i] = si*coeffsx[i][1]
    v[i] = si*ret_xs[i]

mat = Matrix(ZZ, mat)
v = vector(ZZ, v)
t = solve_cvp(mat, v)

x2 = (sf*(t-v)[0] + ret_xs[0])%n1
x3 = (sf*(t-v)[1] + ret_xs[1])%n1

x_state = [x2, x3]
for i in range(3):
    x_state.append((a_1*x_state[-1] + a_2*x_state[-2])%n1)
    
xv = vector(ZZ, x_state)

mat = [[0]*5 for _ in range(7)]
v = [0]*5

for i in range(5):
    mat[i][i] = n2
    mat[5][i] = coeffsy[i][0]%n2
    mat[6][i] = coeffsy[i][1]%n2

mat = Matrix(ZZ, mat)

z = [-1, 0, 1]
dels = list(map(lambda x: vector(ZZ, list(x)), list(itertools.product(z, repeat=5))))

for d in dels:
    v = xv - vector(ZZ, ret_zs) - d*n1
    t = solve_cvp(mat, v)
    if max(v - t).nbits() < 250:
        y_state = list(t)
        k = (b_1*y_state[-1] + b_2*y_state[-2])%n2
        print (long_to_bytes(ct^^k))
        break
```