---
title: "Backdooring Kyber: NIST PQ finalist"
date: 2022-11-15T18:37:48+05:30
draft: false
math: true
---


This is an author writeup for the cryptography challenge "Beyond the mountain" that I created for Backdoor CTF 2021-22. It was based on a backdoor allowing controlled decryption failures that I created for a reduced version of [kyber](https://ieeexplore.ieee.org/abstract/document/8406610). What I personally found interesting in this challenge while creating it was that the attack (atleast as per the intended solution) is based on a technique I personally have yet to see used in any academic work but is very popular in the cryptography CTF community. That technique being, RKM's legendary [Inequality solving with CVP](https://github.com/rkm0959/Inequality_Solving_with_CVP) repo

I'll begin with an introduction of the Kyber Cryptosystem, followed by the challenge and finally the attack

## Notation
$Z_q$ represents the ring of integers mod q. 

$R_q = Z_q[X]/(X^N + 1)$ for N some power of 2. The ring of $l_1 \times l_2$ matrices over $R_q$ is written as $R_q^{l_1 \times l_2}$ 

For $x \in Z_q^n$, $||x||_2$ denotes the $l_2$ norm of $x$. For $x \in R_q$,  $||x||_2$ denotes the $l_2$ norm of $x$ considered as a vector of its coefficients

Similarly $||x||$ = $max(\{|x_i|\ | x_i \in x\})$ denotes the $l_{\infty{}}$ norm of x.

$U(S)$ denotes the uniformly random distribution over the set $S$.
$\chi(S)$ represents small error distribution over the set S (well, technically it has to be a Poset but that's a given for the rings we're working with)

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

### LWE based encryption

The complete functioning of Kyber is explained in the next section. However I'd like to preface it with a simple Ring-LWE based encryption [scheme](https://eprint.iacr.org/2013/293) that highlights the core intuition behind a number of LWE PKEs

## Kyber