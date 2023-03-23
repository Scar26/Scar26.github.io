---
title: " FFT Optimizations for ZK SNARKs"
date: 2023-02-10T15:15:04+05:30
draft: true
---

This post is based on the design of the [bellman](https://github.com/zkcrypto/bellman) library for zk-SNARKs. Though the majority of these optimizations are agnostic to the actual proving algorithm being used, I'll mainly focus on groth16 for now, which is what bellman implements.

## Preliminaries

Basic grasp of R1CS and the [groth16](https://xn--2-umb.com/22/groth16/) proving system. Basic understanding of FFT/NTT

## Overview

There's 2 main classes of speedups that the bellman library utilizes
- Speeding up polynomial operations with Finite Field FFT (or NTT, whatever you wanna call it)
- Parallelizing vector and elliptic curve operations

In this part, we'll discuss only the FFT based optimizations

## Notation

Throughout, we'll assume a constraint system over a finite field $F$.

One constraint in the circuit is represented by 3 vectors $A,B,C \in F^n$. To synthesize a QAP from this constraint system, we interpolate $A, B, C$ on an index by index basis to obtain $A(x), B(x), C(x) \in F[x]^n$. 

**Each index represents one variable in the circuit**. Therefore, if look at, say, the polynomial at index 0 of $A(x)$, it tells us the coefficient for the variable indexed by 0 in each constraint.

A circuit with n variables and m constraints would therefore synthesize to a QAP of the form (here on referred to as the QAP equation)
$$(w.A(x))*(w.B(x)) - w.C(x) = H(x).Z(x)$$

$$w \in F^n\\
A(x), B(x), C(x), H(x), Z(x) \in  F[x]^n$$

Let $X = \{x_i\ |\ i \in [0, m),\ x_i \in F\}$ be a set of points in $F$ chosen for interpolating constraint polynomials. $Z(x)$ is then just $\prod (x-x_i)$ 

A polynomial $p(x)$ in "evaluation domain" means we have the evaluation of $p$ at $m$ values of $x$. In most cases when dealing with FFT, those points correspond to the $m^{th}$ roots of unity.

A polynomial $p(x)$ in "lagrange basis" simply means we're given the vector of its coefficients.

We use FFT to go from lagrange basis to evaluation domain, and iFFT for the inverse in $O(m\log(m ))$ time (as opposed to $O(m^2)$ in the naive approach).

## Parameter generation phase
SNARKs require a trusted setup. Groth16 in particular is a non-universal proof system, meaning that a separate parameter generation ceremony is required for each circuit.

The polynomial vectors $A(x), B(x), C(x)$ specify the circuit and are therefore public. But in the proving phase, we have to compute $w.T(\tau)$ for $T \in \{A, B, C\}$. Note that $\tau$ is destroyed after the SRS generation and what we actually have as part of the trusted setup is $G_1A(\tau), G_1B(\tau), G_1C(\tau)$

So it makes sense to store $G_1A(\tau), G_1B(\tau), G_1C(\tau)$ as part of the proving key instead of the entire polynomial vector. This is useful because:

1. It leads to smaller parameters since we only have to store vectors of field elements instead of polynomials
2. Since $\tau$ is part of the trusted setup (constant), $G_1A(\tau), G_1B(\tau), G_1C(\tau)$ can be precomputed for the proving phase

Since we're still int the parameter generation phase, $\tau$ is known. So our task is to compute $A(\tau), B(\tau), C(\tau)$.


### Evaluation without interpolation
Lets address an individual index of $A(x)$. We have $y_i \in F, i \in [0, m)$. And we interpolate these to obtain a polynomial $a_j(x)$ s.t $a_j(x_i) = y_i, x_i \in X$. $a_j$ represents all constraints on the circuit variable indexed j. Since we choose $X$ to be the roots of unity in $F$, interpolation can be done with inverse FFT. Since what we want to calculate is $a(\tau)$, the naive approach would be

1. Gather all $y_i$ and do iFFT to obtain $a(x)$
2. Evaluate at $\tau$
3. Repeat for all indices

This requires one iFFT operation for each variable in the circuit. Instead we can use a trick to calculate $a_j(\tau)$ without ever interpolating $y_i$. 

Calculate $T=iFFT([\tau^0, \tau^1, \tau^2...\tau^{m-1}])$ = $[t_0, t_1, t_2...t_{m-1}]$

Then, given $y_i$, $a_j(\tau)$ is simply given by $\sum_{i=0}^{m-1}y_i.t_i$. This lets us compute $A(x)$ with one iFFT (for computing $T$) instead of one for each variable.

**Proof:**
Let $a_j = iFFT([y_0, y_1...y_{m-1}]) = [a_0, a_1, a_2...a_{m-1}]$

$T=iFFT([\tau^0, \tau^1, \tau^2...\tau^{m-1}])$ = $[t_0, t_1, t_2...t_{m-1}]$
We have
$$
a_j(\tau) = a_0.\tau^0 + a_1\tau^1...a_{m-1}\tau^{m-1},\\
y_i = a_0(\omega^i)^0 + a_1(\omega^i)^1 ... a_{m-1}(\omega^i)^{m-1},\\
\tau^i = t_0(\omega^i)^0 + t_1(\omega^i)^1 ... t_{m-1}(\omega^i)^{m-1},
$$

Now, 
$$
\sum_{i=0}^{m-1}y_i.t_i = \sum_{i=0}^{m-1}(a_0(\omega^i)^0 + a_1(\omega^i)^1 ... a_{m-1}(\omega^i)^{m-1}).t_i
$$

Refactoring the equation a little bit, we get
$$
\sum_{i=0}^{m-1}y_i.t_i = \sum_{i=0}^{m-1}a_i(t_0(\omega^0)^i + t_1(\omega^1)^i...t_{m-1}(\omega^{m-1})^i)\\
= \sum_{i=0}^{m-1}a_i(t_0(\omega^i)^0 + t_1(\omega^i)^1...t_{m-1}(\omega^i)^{m-1})\\
= \sum_{i=0}^{m-1}a_i\tau^i = a_j(\tau)\\
\implies \sum_{i=0}^{m-1}y_i.t_i = a_j(\tau)
$$

## Proving phase

At its core, what a zk SNARK system aims to prove is knowledge of a witness vector $w$ for the above described QAP equation $(w.A(x))*(w.B(x)) - w.C(x) = H(x).Z(x)$

For this we need to compute $H(x)$ which we can get by dividing $(w.A(x))*(w.B(x)) - w.C(x)$ by $Z(x)$. That's 2 polynomial multiplications and one division, pretty standard usecase for FFT... with one caveat. $Z(x)$ is chosen so as to be 0 over the set $X$ which is our FFT basis. So how do we divide by Z when it's just 0 on all the points in our evaluation domain?

### Coset FFT
We use coset-FFT for division with polynomials that evaluate to zero at one or more of the roots of unity. Which is to say, instead of getting evaluations at $\omega^i$, we get evaluations at $S\omega^i$ where $S \in F$ is a fixed element.

Note: $S$ is typically chosen to be the multiplicative generator of the field, but any high order element would work in theory.

The algorithm is pretty simple. Given a polynomial $p$ in lagrange basis,

$$
p = [a_0, a_1...a_{m-1}]
$$

The coset FFT is simply 

$$
FFT([a_0, a_1S, a_2S^2...a_{m-1}S^{m-1}])
$$

The explanation is also pretty simple. FFT gives us evaluations of $p$ at roots of unity, i.e $\sum_{i=0}^{m-1}a_i\omega^i$

Now let $b_i = a_iS^i$

Then FFT would give us elements of the form
$$
\sum_{i=0}^{m-1}b_i(\omega^j)^i, j \in [0,m)\\
= \sum_{i=0}^{m-1}a_iS^i(\omega^j)^i
= \sum_{i=0}^{m-1}a_i(S\omega^j)^i\\
= p(S\omega^j), j \in [0,m)
$$

To take the inverse of a coset FFT, we just take iFFT and then divide the coefficients with the corresponding powers of $S$.

Additionally:
Now $Z(x)=\prod (x-\omega^i) = x^m - 1$.

Since $(\omega^i)^m = 1 \forall i \in [0,m)$, we don't even need to compute FFT to get the evaluation of $Z(S\omega^i)$ at the roots of unity, since it will have the same value $S^m - 1$ at all the evaluation points.

Now to compute H(x), we first obtain $CosetFFT(w.A(x)*w.B(x) - w.C(x))$

1. The multiplication of A and B is also performed by taking FFT normally followed by iFFT to convert the result back to lagrange basis
2. We now have the evaluation of $w.A(x)*w.B(x) - w.C(x)$ at the points $S.(\omega^i)$
3. Divide each of these by $S^m - 1$ (evaluation of Z at all these points)
4. Take inverse coset FFT as described above

We now have H(x) in the lagrange basis

## Implementations
Here's a sample implementation of coset FFT from my [groth16 library](https://github.com/Scar26/embedded-groth/blob/master/src/poly.rs)

```rust!
pub fn coset_fft<S: PrimeField>(a: &mut [S], omega: &S, exp: u32) {
    let g = S::multiplicative_generator();
    let mut u = S::one();
    for x in a.iter_mut() {
        x.mul_assign(&u);
        u.mul_assign(&g);
    }
    fft(a, omega, exp)
}

pub fn icoset_fft<S: PrimeField>(a: &mut [S], omega: &S, exp: u32) {
    ifft(a, omega, exp);
    let g = S::multiplicative_generator().invert().unwrap();
    let mut u = S::one();
    for x in a.iter_mut() {
        x.mul_assign(&u);
        u.mul_assign(&g);
    }
}

``` 