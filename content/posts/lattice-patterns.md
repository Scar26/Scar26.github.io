---
title: "Lattice Patterns for Cryptanalysis of Linear systems"
date: 2023-03-24T12:35:40+05:30
draft: true
math: true
---

The goal of this post is to document some common Lattice patterns I've come across while trying to break **linear** cryptosystems during CTFs. Documenting my lattice toolkit, so to speak.

I say linear because analyzing anything non-linear with lattices is almost always going to boil down to coppersmith hackery. And since coppersmith abstracts the lattice part away, it becomes more a matter of clobbering parameters than coming up with a nice lattice. These problems essentially revolve around beating your equations into a form where coppersmith can feasibly work.

I'll update this post as new patterns pop up/come to mind.

