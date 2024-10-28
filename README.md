Common Signing Library with Russian GOST Algorithms support
=======================================
[![Build Status](https://travis-ci.com/i-novus-llc/common-sign-gost.svg?branch=master)](https://travis-ci.com/i-novus-llc/common-sign-gost)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Known Vulnerabilities](https://snyk.io/test/github/i-novus-llc/common-sign-gost/badge.svg)](https://snyk.io/test/github/i-novus-llc/common-sign-gost)

This library is based on *org.apache.santuario:xmlsec* and extends it by GOST 2001 and GOST 2012 256/512 algorithms.

The library allows calculate hash by GOST algorithms, sign files, string, byte arrays and so on, verify digital signatures.
Additionaly, it contains methods to sign requests to SMEV 3 (http://smev3.gosuslugi.ru), Minzdrav IPS (https://portal.egisz.rosminzdrav.ru/materials/11).  

Based on Bouncy Castle libraries.  
----
Copyright (C) 2018-2024 I-Novus, LLC
