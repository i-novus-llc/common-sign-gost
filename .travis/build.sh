#!/bin/bash

if [[ $TRAVIS_TAG == '' ]] ; then
  mvn clean install -B -U
else
  openssl aes-256-cbc -K $encrypted_8df87fe9d1be_key -iv $encrypted_8df87fe9d1be_iv -in .travis/my.travis.gpg.enc -out my.travis.gpg -d
  mvn --settings .travis/.maven.xml clean deploy -Prelease -B -U
fi