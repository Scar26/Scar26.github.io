---
title: "Practical ZK SNARKs: Optimizations"
date: 2023-02-10T15:15:04+05:30
draft: true
---

This post is based on the design of the [bellman](https://github.com/zkcrypto/bellman) library for zk-SNARKs. Though the majority of these optimizations are agnostic to the actual proving algorithm being used, I'll mainly focus on groth16 for now, which is what bellam implements.

## Preliminaries

Basic grasp of R1CS the [groth16](https://xn--2-umb.com/22/groth16/) proving system.

## Overview

There's 2 main classes of speedups that the bellman library utilizes
- Parallelizing vector and elliptic curve operations
- Speeding up polynomial operations with Finite Field FFT (or NTT, whatever you wanna call it)

## Notation
Throughout, we'll assume a constraint system over a finite field $F$.

One constraint in the circuit is represented by 3 vectors $A,B,C \in F^n$. To synthesize a QAP from this constraint system, we interpolate 

A circuit with n variables and m constraints would therefore synthesize to a QAP of the form (here on referred to as the QAP equation)
$$(w.A(x))*(w.B(x)) - w.C(x) = H(x).Z(x)$$

$$w \in F^n\\
A(x), B(x), C(x), H(x), Z(x) \in  F[x]^n$$

Let $X = \{x_i\ |\ i \in [0, m),\ x_i \in F\}$ be a set of points in $F$ chosen for interpolating constraint polynomials. $Z(x)$ is then just $\prod (x-x_i)$ 


## FFT Optimizations

At its core, what a zk SNARK system aims to prove is knowledge of a witness vector $w$ for the above described QAP equation.

The dot product involves  