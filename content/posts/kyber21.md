---
title: "Backdooring Kyber: NIST PQ finalist"
date: 2022-01-11T18:37:48+05:30
draft: true
math: true
---


This is an author writeup for the cryptography challenge "Beyond the mountain" that I created for Backdoor CTF 2021-22. It was based on a backdoor that I came up with for a slightly reduced version of [kyber](https://ieeexplore.ieee.org/abstract/document/8406610). The backdoor allows us to create "controlled decryption failures" in polynomial time. 

What I personally found interesting in this challenge while creating it was that the attack is based on a technique I personally have yet to see used in any academic work but is very popular in the cryptography CTF community. That technique being, RKM's legendary [Inequality solving with CVP](https://github.com/rkm0959/Inequality_Solving_with_CVP) repo. Though I did have to extend the logic from RKM's repo to get this attack working, the basic intuition is the same

I'll begin with an introduction of the Kyber Cryptosystem, followed by the challenge and finally the attack.

## Notation
$Z_q$ represents the ring of integers mod q. I'll be using the $[-\frac{q}{2}, \frac{q}{2}]$ representation because it's more intuitive for some encoding stuff easier as you'll see later. This is gonna be kind of important so make sure you understand it well

$R_q = Z_q[X]/(X^N + 1)$ for N some power of 2. The ring of $l_1 \times l_2$ matrices over $R_q$ is written as $R_q^{l_1 \times l_2}$.

Elements of $R_q$ are written as polynomials in the indeterminate $u$

For $x \in Z_q^n$, $||x||_2$ denotes the $l_2$ norm of $x$. For $x \in R_q$,  $||x||_2$ denotes the $l_2$ norm of $x$ considered as a vector of its coefficients

Similarly $||x||_{\infty} = max(\{|x_i|\ | x_i \in x\})$ denotes the $l_{\infty}$ norm of x.

$U(S)$ denotes the uniformly random distribution over the set $S$.
$\chi(S)$ represents a small binomial distribution centered around 0 (well, technically it has to be a Poset but that's a given for the rings we're working with). The exact distribution doesn't really matter for intuition, just think of it as as a small distribution centered around 0

## Background

CRYSTALS-Kyber is a Module LWE based PKE scheme that, at the time of writing, is one of finalist candidates in the NIST Post Quantum competition.

### Mod LWE

The LWE (Learning with Errors) problem is an extension of the LPN (Learning Parity with Noise) problem and is described as follows.

For a random secret vector $s \in Z_q^n$, the adversary is given an aribitrary number of samples of the form 
$$(a, a^Ts + e) \in Z_q^n \times Z_q$$ $$a \leftarrow U(Z_q^n), e \leftarrow \chi(Z_q)$$

The LWE problem is then to obtain $s$ from the given samples. Under the LWE assumption, this problem assumed to be hard.

For **Ring LWE**, $Z_q$ is replaced with $R_q$. So $a, s, e \in R_q$ and the samples are of the form
$$(a, a.s + e) \in R_q \times R_q$$

Finally, for **Module LWE**, $s, a \in R_q^{l \times 1}$, i.e a module of $R_q$ leading to samples of the form
$$(a, a^Ts + e) \in R_q^{l \times 1} \times R_q$$

## Kyber

As standard for PKEs, Kyber is described by the triplet of functions
$$KeyGen()\\ 
Enc(pk = (\textbf{t}, \rho), m)\\ 
Dec(sk=\textbf{s}, ct = (u, v))$$

### Key Generation
$s, e \leftarrow \chi(R_q^{l \times 1})$

Start by selecting some random bits (256 bits in the kyber spec) $\rho$. And using it as a randomness seed to generate a matrix $A \in R_q^{l \times l} = genA(\rho)$

$t = A \times s + e$

Output $s$ as private key and $b$ as public key

Sage implementation:
```python
// mimic a small centered binomial distribution
def small_poly():
    return Rq([randint(1, 4) for _ in range(N)])

def genA(base_ring, r, l):
    random.seed(r)
    A = Matrix(base_ring, [[base_ring([Integer(random.randint(0, q-1)) for _ in range(N)]) for _ in range(l)] for _ in range(l)])
    return A
    
def keygen():
    global l
    r = Integer(random.getrandbits(N))
    A = genA(Rq, r, l)
    s = vector(Rq, [small_poly() for _ in range(l)])
    e = vector(Rq, [small_poly() for _ in range(l)])
    t = A*s + e

    return (t, r), (s, e)
```

### Encryption
Input: m = plaintext, pk = ($t = genA(\rho)*s + e, \rho$)

**Important**: Bitlength of m <= N

$$(s', e', e'') \leftarrow \chi(R_q^{l \times 1} \times R_q^{l \times 1} \times R_q)$$

$$A = genA(\rho)\\
u = A^Ts' + e' \in R_q^{l \times 1}\\
v = t^Ts' + e'' + \frac{q}{2}m \in R_q$$


Wait! Wasn't m supposed to be plaintext? Why, yes it was. We first need to encode it to $R_q$.

To do this, construct a polynomial by using the ith least significant bit of m as the coefficient for $u^i$. Then we multiply this polynomial by $\frac{q}{2}$. So the resulting encoding is a element of $R_q$ with coefficients in only $\{0, \frac{q}{2}\}$. 

```python
def encode(m):
        m = list(map(int, bin(m)[2:][::-1]))
        m = Rq(m)
        return m*q//2
```

We then output the Ciphertext $$(u, v)$$

The complete Encryption Routine looks like this
```python
def encrypt(pk, m, r, e1):
    t, rh = pk
    t = vector(Rq, t)
    A = genA(Rq, rh, l)
    m = list(map(int, bin(m)[2:][::-1]))
    m = Rq(m)
    e2 = small_poly()
    u = A.transpose()*r + e1
    v = t*r + e2 + (q//2)*m
    return (u, v)
```
r and e1 are $s'$ and $e'$ that we accept as user input

Except this is not the complete Kyber encryption routine. In the real Kyber, we have

$$u = Compress_q(A^Ts' + e')\\
v =  Compress_q(t^Ts' + e'' + \frac{q}{2}m)$$

Kyber uses 2 special functions Compress and Decompress. Compress maps $x \in Z_q$ to an integer $y \in \{0...2^d - 1\}$ for some $d < \log_2(q)$. Decompress does the opposite (duh), but obviously there's some deterministic error introduced by the compression. i.e For $x \in Z_q$,
$$r = x - Decompress_q(Compress_q(x))$$

has a small non-zero distribution. In the challenge, I actually dropped these 2 routines. Reason: though the attack can probably be adjusted (might investigate further at some point) to work with the compression error, it does complicate things and I couldn't figure it out in time. 

### Decryption
Input sk = s, ct = (u, v)

For decryption, we just compute $decode(round(v - s^Tu))$

Let's open up the equation

$$
v - s^Tu\\
= t^Ts' + e'' + \frac{q}{2}m - s^T(A^Ts' + e')\\
= (As + e)^Ts' + e'' + \frac{q}{2}m - s^T(A^Ts' + e')\\
= s^TA^Ts' + e^Ts' + e'' + \frac{q}{2}m - s^TA^Ts' - s^Te'\\
= \frac{q}{2}m + (e^Ts' + e'' - s^Te')
$$

Let $r = e^Ts' + e'' - s^Te'$

$r$ consists entirely of $R_q$ elements derived from "small" distributions.  So we can "round" $c = \frac{q}{2}m + r$ to get m. This is done as follows:

Let's write c as $c = \sum_{i=0}^{N-1}c_iu^i$. The contribution of $r$ to $c_i$ is small.

Hence if $c_i \in (-\frac{q}{4}, \frac{q}{4})$ (which can be written as $(0, \frac{q}{4}) \cup (\frac{3q}{4}, q)$), $b_i = 0$. Otherwise $b_i$ = 1.

Where $b_i$ is the ith bit of m.

```python
def decode(base_ring, v):
    v = list(v).copy()
    for i, p in enumerate(v):
        coefs = p.list()
        for j, a in enumerate(coefs):
            coefs[j] = round((2/q)*Integer(a))%2
        v[i] = base_ring(coefs)
    return v
    
def decrypt(sk, ct):
    u, v = ct
    m = decode(Rq, [v - sk*u])[0]
    m = m.list()[::-1]
    return int(''.join(map(str, m)), 2)
```

## Challenge
Here's the complete challenge source
```python
import random

q = 3329
R = Zmod(q)
N = 32
l = 2
d = 11
Rx.<x> = PolynomialRing(R)
Rq.<u> = Rx.quotient(x^N + 1)

flag =  open("flag.txt").read()

# My not so secret keys
# Static keys so you can precompute part of the solution to spare our poor VPS some load
t = vector(Rq, [3299*u^31 + 3045*u^30 + 2395*u^29 + 742*u^28 + 2092*u^27 + 22*u^26 + 2323*u^25 + 506*u^24 + 2532*u^23 + 5*u^22 + 1565*u^21 + 704*u^20 + 355*u^19 + 1766*u^18 + 1307*u^17 + 1148*u^16 + 1194*u^15 + 2260*u^14 + 1999*u^13 + 1188*u^12 + 731*u^11 + 68*u^10 + 847*u^9 + 2090*u^8 + 2514*u^7 + 3252*u^6 + 997*u^5 + 2271*u^4 + 731*u^3 + 1937*u^2 + 7*u + 2574, 2383*u^31 + 3121*u^30 + 963*u^29 + 1495*u^28 + 2776*u^27 + 2541*u^26 + 2516*u^25 + 2667*u^24 + 2772*u^23 + 114*u^22 + 1762*u^21 + 366*u^20 + 1343*u^19 + 2521*u^18 + 1678*u^17 + 3224*u^16 + 510*u^15 + 1594*u^14 + 3020*u^13 + 3145*u^12 + 1114*u^11 + 1823*u^10 + 1081*u^9 + 1737*u^8 + 2821*u^7 + 2202*u^6 + 2355*u^5 + 2238*u^4 + 745*u^3 + 266*u^2 + 887*u + 2731])
rh = 3428567257
s = vector(Rq, [4*u^31 + u^30 + 2*u^29 + u^28 + 4*u^27 + u^26 + 3*u^25 + 4*u^24 + 3*u^23 + u^22 + 2*u^21 + 4*u^20 + 3*u^19 + u^18 + u^17 + 3*u^16 + 2*u^15 + 2*u^14 + 4*u^13 + 4*u^12 + 2*u^11 + u^10 + u^9 + u^8 + u^7 + 2*u^6 + 4*u^5 + 2*u^4 + 3*u^3 + 4*u^2 + 3*u + 2, 4*u^31 + u^30 + 2*u^29 + 4*u^28 + u^27 + 3*u^26 + 2*u^25 + u^24 + u^23 + 3*u^22 + 4*u^21 + u^20 + u^19 + 4*u^18 + 3*u^17 + u^16 + u^15 + 3*u^14 + 3*u^13 + 3*u^12 + 3*u^11 + 3*u^10 + u^9 + 4*u^8 + 3*u^7 + 4*u^6 + 2*u^5 + 2*u^4 + u^3 + u^2 + 4*u + 4])
e = vector(Rq, [3325*u^31 + 5*u^30 + 3325*u^29 + 3325*u^28 + 3324*u^27 + 4*u^26 + 5*u^25 + 3324*u^24 + 3324*u^23 + 3324*u^22 + 5*u^21 + 3325*u^20 + 5*u^19 + 3325*u^18 + 5*u^17 + 3325*u^16 + 3326*u^15 + 3325*u^14 + 3328*u^13 + 3327*u^12 + 3325*u^11 + 3326*u^10 + 3327*u^9 + 3328*u^8 + 3327*u^7 + 3325*u^6 + 3325*u^5 + 3327*u^4 + 3326*u^3 + 3328*u^2 + 3328*u + 3325, 3325*u^31 + 5*u^30 + 5*u^29 + 3325*u^28 + 3325*u^27 + 4*u^26 + 3324*u^25 + 3325*u^24 + 3325*u^23 + 3324*u^22 + 3325*u^21 + 4*u^20 + 4*u^19 + 3325*u^18 + 3324*u^17 + 4*u^16 + 3325*u^15 + 4*u^14 + 5*u^13 + 4*u^12 + 3324*u^11 + 5*u^10 + 5*u^9 + 3324*u^8 + 5*u^7 + 4*u^6 + 5*u^5 + 3324*u^4 + 4*u^3 + 3324*u^2 + 5*u + 3325])

pk = (t, rh)
sk = (s, e)

def genA(base_ring, r, l):
    random.seed(r)
    A = Matrix(base_ring, [[base_ring([Integer(random.randint(0, q-1)) for _ in range(N)]) for _ in range(l)] for _ in range(l)])
    return A

def decode(base_ring, v):
    v = list(v).copy()
    for i, p in enumerate(v):
        coefs = p.list()
        for j, a in enumerate(coefs):
            coefs[j] = round((2/q)*Integer(a))%2
        v[i] = base_ring(coefs)
    return v

def small_secret():
    return Rq([randint(1, 4) for _ in range(N)])

def small_error():
    return Rq([randint(-4, -1) for _ in range(N)])

# In case you plebs think testing it locally will make it any easier
def keygen():
    global l
    r = Integer(random.getrandbits(N))
    A = genA(Rq, r, l)
    s = vector(Rq, [small_secret() for _ in range(l)])
    e = vector(Rq, [small_error() for _ in range(l)])
    t = A*s + e

    return (t, r), (s, e)

def encrypt(pk, m, r, e1):
    t, rh = pk
    t = vector(Rq, t)
    A = genA(Rq, rh, l)
    m = list(map(int, bin(m)[2:][::-1]))
    m = Rq(m)
    e2 = small_error()
    u = A.transpose()*r + e1
    v = t*r + e2 + (q//2)*m
    return (u, v)

def decrypt(sk, ct):
    u, v = ct
    m = decode(Rq, [v - sk*u])[0]
    m = m.list()[::-1]
    return int(''.join(map(str, m)), 2)

def verify_small_vector(v):
    return all([-6 <= i <= 6 for i in v[:-1]])

def flatten(u):
    b = []
    for i in u:
        j = i.list()
        j = j + [0]*(N-len(j))
        b += j
    return vector(R, b)

def unflatten(base_ring, v):
    v = list(v)
    return vector(base_ring, [base_ring(v[i*N: (i+1)*N]) for i in range(len(v)//N)])

def receive_vector():
    """
    What you want to input here is a vector of dimension l over Rq.
    The way to do that is to create your vector, call the function "flatten" on it,
    and then send the resulting list as comma separated integers
    e.g: if your vector is v, you need to send str(flatten(v)).replace("[", "").replace("]", "")
    """
    a = input("Enter vector: ")
    a = list(map(Integer, a.split(",")))
    
    if len(a) != N*l:
        print ("It's just a simple math challenge, no pwn trickery please")
        exit()

    if not verify_small_vector(a):
        print ("Is an error even an error if it's not small")
        exit()
    
    return unflatten(Rq, a)

for _ in range(5):
    pt = randint(0, 2^11)
    print ("plaintext: ", pt)
    challenge = 2^randint(0, 11)
    print ("challenge: ", challenge)
    r = receive_vector()
    e1 = receive_vector()
    dif = decrypt(sk[0], encrypt(pk, pt, r, e1))^^pt
    if dif != challenge:
        print ("So much for perfect correctness")
        exit()

print ("OK, you win. Here's your flag")
print (flag)
```

There's encryption and decryption implemented. It's mostly standard kyber. It's only "reduced" in the following 2 ways. Both the secret and public key are known (they're static but they're randomly generated. That was genuinely just to save our poor server some load)

The player is given a plaintext and a bit index from 0-11. The player is allowed to povide the randomness $s', e'$ for the encryption function, such that only the bit at the provided index is flipped when it's decrypted. Hence "controlled decryption failure" since we're required to control which bits are flipped by the failure.

Repeat 5 times
???
Flag!

## Decryption Failure

It's clear from the decryption function that Kyber does not have **perfect correctness**. Which is really an issue with most LWE based encryption schemes. Meaning that in rare cases, we may encounter a "decryption failure". A decryption failure is the event where
$$m \neq Decrypt_{sk}(Encrypt_{pk}(m))$$

To model a failure, we'll borrow some notation from the "[failure boosting](https://eprint.iacr.org/2019/1399.pdf)" line of research on Kyber (which I will not be going into here, just stealing their tools).

The final error as derived in the decryption section was $r = e^Ts' + e'' - s^Te'$

Let $S = \left[\begin{matrix}
-s \newline
e
\end{matrix}\right]$   $C = \left[\begin{matrix}
e' \newline
s'
\end{matrix}\right]$ $G = e''$
Then,
$$r = S^TC + G$$
And a failure occurs when $||r||_{\infty} = ||S^TC + G||_{\infty} > \frac{q}{4}$ i.e 
$$\frac{q}{4} \leq ||S^TC + G||_{\infty} \leq \frac{3q}{4}$$
Since G is small,
$$\frac{q}{4} \leq ||S^TC||_{\infty} \leq \frac{3q}{4}$$
Note that S is made of elements in the secret key (known), C is made of encryption randomness (which the attacker controls). So for the challenge given S, we need to find C such that coefficient of $u^i$ in $S^TC$ is in $(\frac{q}{4}, \frac{3q}{4})$

The following transformation (also stolen from [here](https://eprint.iacr.org/2019/1399.pdf)) can be used to calculate these coefficients individually

For $X \in R_q^{l \times 1}$, $\bar{X} \in Z_q^{lN \times 1}$ is the representation of $X$ where each polynomial in $R_q$ is decomposed into a list of its coefficients in $Z_q$.

```python
def bar(base_ring, u, v):
    b = []
    for i in u:
        j = i.list()
        j = j + [0]*(N-len(j))
        b += j
    for i in v:
        j = i.list()
        j = j + [0]*(N-len(j))
        b += j
    return vector(base_ring, b)
```

For $C \in R_q^{l \times 1}$,
$$C^{(r)} = X^rC(X^{-1})\mod X^N + 1$$

$C^{(r)}$ is called the rotation of $C$ by r

```python
def evalinv(c):
    c = list(c).copy()
    for i, p in enumerate(c):
        c[i] = sum([x*(u^-j) for j,x in enumerate(p.list())])
    return vector(Rq, c)

def rotation(c, r):
    return (u^r)*evalinv(c)
```

It is easy to verify that

$$S^TC = \sum_{i=0}^{N-1}\bar{S}^T\bar{C^{(i)}}.u^i$$

Now we can rewrite our problem statement as: Given $S$, to cause a decryption failure that flips the ith bit, we need  to find a $C$ that satisfies $\bar{S}^T\bar{C^{(i)}} \in (\frac{q}{4}, \frac{3q}{4})$

## Attack

Since C is completely made of small terms (and as a result so is any rotation of C), corrupting a bit boils down to computing small solutions for a linear inequality in $Z_q$.  (What you get after the inequality is a rotation of C, to corrupt a specific bit i, just reverse rotate it by i to obtain C). This is starting to smell eerily like a lattice problem.

To solve this inequality, you can extend the logic from rkm's inequality CVP repo. The inequality repo basically hypothesizes: to solve a system of linear inequations with upper and lower bounds $(u_i, l_i)$, we create a lattice using the inequations coefficients as the basis. Intuitively, if we had a solution vector, all the inequalities should "on average" be close to the mean of their respective bounds ($\frac{u_i + l_i}{2}$). So construct a target vector using these bound means and solve CVP in our coefficient lattice. Note that the inequality repo won't work directly here because it won't give a small enough solution if we just solve cvp with the mean of bounds.

So the way to extend it is that instead of 

There's roughly 1500 targets for the CVP between q/4 and 3q/4 but you only need to try about 500 values around q/2 to obtain solutions that fit within range (Much like rkm's repo, I don't have a mathematical proof for why this works, but it makes intuitive sense if you think about it). Once you find said small solution, you just need to send reverse rotations of it for corrupting any bit you want and get the flag