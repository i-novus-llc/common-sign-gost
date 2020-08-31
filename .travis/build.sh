#!/bin/bash

if [[ $TRAVIS_TAG == '' ]] ; then
  mvn --settings .travis/.maven.xml clean install -B -U
else
  openssl aes-256-cbc -K $encrypted_286124008a61_key -iv $encrypted_286124008a61_iv -in .travis/.my.travis.gpg.enc -out .travis/.my.travis.gpg -d
  mvn --settings .travis/.maven.xml clean deploy -Prelease -B -U
fi