---
title: "Cryptohack: Modular Arithmetic"
date: 2022-10-29T20:05:14-07:00
draft: true
categories: ["cryptohack"]
tags: ["crypto"]
---

My notes and solutions to Cryptohack's Modular Arithmetic section

<!--more-->

## Greatest Common Divisor
>The Greatest Common Divisor (`GCD`), sometimes known as the highest common factor, is the largest number which divides two positive integers (`a`,`b`).
>
>For `a = 12`, `b = 8` we can calculate the divisors of `a: {1,2,3,4,6,12}` and the divisors of `b: {1,2,4,8}`. Comparing these two, we see that `gcd(a,b) = 4`.
>
>Now imagine we take `a = 11`, `b = 17`. Both `a` and `b` are prime numbers. As a prime number has only itself and `1` as divisors, `gcd(a,b) = 1`.
>
>We say that for any two integers `a,b`, if `gcd(a,b) = 1` then a and b are **coprime** integers.
>
>If `a` and `b` are prime, they are also coprime. If `a` is prime and `b` < `a` then `a` and `b` are coprime.
>There are many tools to calculate the GCD of two integers, but for this task we recommend looking up [Euclid's Algorithm](https://en.wikipedia.org/wiki/Euclidean_algorithm).
>
>Try coding it up; it's only a couple of lines. Use `a = 12, b = 8` to test it.
>
>Now calculate `gcd(a,b)` for `a = 66528, b = 52920` and enter it below.

`Euclid's Algorithm` pseudocode:
```java
function gcd(a, b)
    while a ≠ b 
        if a > b
            a := a − b
        else
            b := b − a
    return a
```
```java
function gcd(a, b)
    if b = 0
        return a
    else
        return gcd(b, a mod b)
```

### Solution

```python
def gcd(a,b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)
```
```console
> gcd(12, 8)
4
> gcd(66528, 52920)
1512
```

## Extended GCD
>Let `a` and `b` be positive integers.
>
>The extended Euclidean algorithm is an efficient way to find integers `u,v` such that `a * u + b * v = gcd(a,b)`
>
>Using the two primes `p = 26513, q = 32321`, find the integers `u,v` such that `p * u + q * v = gcd(p,q)`
>
>Enter whichever of u and v is the lower number as the flag.

### Solution
I watched [this video](https://www.youtube.com/watch?v=hB34-GSDT3k) and read [this article](http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html) to better understand the extended Euclidean Algorithm.
```python
# function for extended Euclidean Algorithm
def gcdExtended(a, b):
    # Base Case
    if a == 0 :
        return b,0,1

    gcd,x1,y1 = gcdExtended(b%a, a)

    # Update x and y using results of recursive call
    x = y1 - (b//a) * x1
    y = x1

    return gcd,x,y
```
*reference: https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/*

```console
> gcdExtended(26513, 32321)
(1, 10245, -8404)
> min(10245, -8404)
-8404
```

## Modular Arithmetic 1
> Imagine you lean over and look at a cryptographer's notebook. You see some notes in the margin:
```
4 + 9 = 1
5 - 7 = 10
2 + 3 = 5
```
>At first you might think they've gone mad. Maybe this is why there are so many data leaks nowadays you'd think, but this is nothing more than modular arithmetic modulo 12 (albeit with some sloppy notation).
>
>You may not have been calling it modular arithmetic, but you've been doing these kinds of calculations since you learnt to tell the time (look again at those equations and think about adding hours).
>
>Formally, "calculating time" is described by the theory of congruences. We say that two integers are congruent modulo m if `a ≡ b mod m`.
>
>Another way of saying this, is that when we divide the integer `a` by `m`, the remainder is `b`. This tells you that if m divides a (this can be written as `m | a`) then `a ≡ 0 mod m`.
>
>Calculate the following integers:
```
11 ≡ x mod 6
8146798528947 ≡ y mod 17
```
>The solution is the smaller of the two integers.

### Solution
[*if `a ≡ b mod m`, then `b ≡ a mod m`.*](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/https://www.math.nyu.edu/~hausner/congruence.pdf)

So:

`11 ≡ x mod 6` -> `x ≡ 11 mod 6` -> `x ≡ 5`

`8146798528947 ≡ y mod 17` -> `y ≡ 8146798528947 mod 17` -> `y ≡ 4`

```console
> min(11 % 6, 8146798528947 % 17)
4
```

## Modular Arithmetic 2
>We'll pick up from the last challenge and imagine we've picked a modulus `p`, and we will restrict ourselves to the case when `p` is prime.
>
>The integers modulo `p` define a field, denoted `Fp`.
>
>A finite field `Fp` is the set of integers `{0,1,...,p-1}`, and under both addition and multiplication there is an inverse element `b` for every element `a` in the set, such that `a + b = 0` and `a * b = 1`.
>
>Lets say we pick `p = 17`. Calculate `3^17 mod 17`. Now do the same but with `5^17 mod 17`.
>
>What would you expect to get for `7^16 mod 17`? Try calculating that.
>
>This interesting fact is known as Fermat's little theorem. We'll be needing this (and its generalisations) when we look at RSA cryptography.
>
>Now take the prime `p = 65537`. Calculate `273246787654^65536 mod 65537`.
>
>Did you need a calculator?

### Solution
In summary, [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem) states that:

```
if p is prime, for every integer a:
    pow(a, p) = a mod p
and, if p is prime and a is an integer coprime with p:
    pow(a, p-1) = 1 mod p
```

So:
```python
from math import gcd

a = 273246787654
p = 65537

if gcd(a,p) == 1:
    print("Coprime! Solution is 1")
```

## Modular Inverting

### Solution
